#include "security.h"
#include "platform.h"
#include <string.h>
#include <stdlib.h>

/* Flash addresses for persistent crypto state */
#define FLASH_ADDR_COUNTER_PRIMARY 0x10000
#define FLASH_ADDR_IDENTITY_KEY    0x40000

/* Session timeout: invalidate after this long without refresh */
#define SESSION_TIMEOUT_MS (3600 * 1000) /* 1 hour */

/* Module state */
static struct {
    uint8_t mode;
    uint8_t cipher;
    uint8_t node_id[NODE_ID_LENGTH];
    uint8_t device_secret[32];               /* HMAC/integrity secret stored in flash */
    monotonic_counter_t counter_primary;     /* Persistent monotonic nonce base */

    /* Identity key pair used for handshake ECDH */
    uint8_t id_pub[PUBLIC_KEY_LENGTH];
    uint8_t id_priv[PRIVATE_KEY_LENGTH];
    uint8_t identity_loaded;

    /* Per-peer session table */
    session_info_t sessions[MAX_ACTIVE_SESSIONS];

    /* Group keys: one per joined group */
    group_key_info_t groups[MAX_GROUP_KEYS];

} sec_state;

/**
 * Computes an HMAC-SHA-256 integrity hash for a monotonic counter value.
 *
 * @param ctr Counter whose value is authenticated.
 * @param out_hash Buffer receiving the 32-byte hash.
 * @return 0 on success.
 */

static int compute_counter_hmac(const monotonic_counter_t* ctr, uint8_t out_hash[32]) {
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, sec_state.device_secret, 32);
    crypto_auth_hmacsha256_update(&st, (const uint8_t*)&ctr->value, sizeof(ctr->value));
    crypto_auth_hmacsha256_final(&st, out_hash);
    return 0;
}

/**
 * Initializes the security subsystem and loads or creates its persistent cryptographic state.
 *
 * @param mode Security operating mode.
 * @param cipher Required cipher configuration.
 * @return 0 on success, -1 if initialization fails or the configuration is unsupported.
 */

int security_init(uint8_t mode, uint8_t cipher) {
    if (sodium_init() < 0) {
        return -1;
    }
    if (mode > SECURITY_E2E_AUTH || cipher != CIPHER_XCHACHA20_POLY) {
        return -1;
    }

    sec_state.mode = mode;
    sec_state.cipher = cipher;
    sec_state.identity_loaded = 0;
    memset(&sec_state.sessions, 0, sizeof(sec_state.sessions));

    /* Load or generate device secret used for HMAC of stored data.
     * NOTE: In production, this should be derived from hardware calibration area,
     * secure element (ATECC608B/C), or factory-provisioned unique key rather than
     * stored as raw bytes in flash memory here. This plaintext storage is acceptable
     * for simulation/demo on Linux but must be hardened for deployed hardware. */
    uint8_t tmp_secret[32];
    if (platform_flash_read(FLASH_ADDR_IDENTITY_KEY + 128, tmp_secret, 32) == 0 &&
        !sodium_is_zero(tmp_secret, 32)) {
        memcpy(sec_state.device_secret, tmp_secret, 32);
    } else {
        randombytes_buf(sec_state.device_secret, 32);
        platform_flash_write(FLASH_ADDR_IDENTITY_KEY + 128, sec_state.device_secret, 32);
    }

    /* Unique device ID */
    platform_get_unique_id(sec_state.node_id, NODE_ID_LENGTH);

    /* Load monotonic counter from flash or initialize new.
     * Counter is HMAC-integrity-protected to detect corruption. On first boot or
     * invalid flash state, we randomize the start point within a large range to avoid
     * nonce collisions across nodes that may be provisioned in parallel. */
    memset(&sec_state.counter_primary, 0, sizeof(monotonic_counter_t));
    uint8_t stored_ctr[sizeof(monotonic_counter_t)];
    platform_flash_read(FLASH_ADDR_COUNTER_PRIMARY, stored_ctr, sizeof(stored_ctr));
    memcpy(&sec_state.counter_primary, stored_ctr, sizeof(monotonic_counter_t));

    if (sec_state.counter_primary.valid) {
        uint8_t check_hash[32];
        compute_counter_hmac(&sec_state.counter_primary, check_hash);
        if (sodium_memcmp(check_hash, sec_state.counter_primary.hash, 32) != 0) {
            sec_state.counter_primary.valid = 0;
        }
    }

    if (!sec_state.counter_primary.valid) {
        sec_state.counter_primary.value = 1000000UL + (uint64_t)(randombytes_uniform(1000000));
        sec_state.counter_primary.timestamp = platform_get_time_ms();
        compute_counter_hmac(&sec_state.counter_primary, sec_state.counter_primary.hash);
        sec_state.counter_primary.valid = 1;
        memcpy(stored_ctr, &sec_state.counter_primary, sizeof(monotonic_counter_t));
        platform_flash_write(FLASH_ADDR_COUNTER_PRIMARY, stored_ctr, sizeof(monotonic_counter_t));
    }

    /* Load or generate identity key pair */
    if (security_load_identity_keys(sec_state.id_pub, sec_state.id_priv) != 0) {
        return -1;
    }

    return 0;
}

/**
 * Copies the loaded identity public key to the specified buffer.
 * @param out_pubkey Buffer that receives the public key.
 * @return 0 on success, or -1 if the output buffer is null or the identity key is not loaded.
 */
int security_get_identity_public_key(uint8_t* out_pubkey) {
    if (!out_pubkey || !sec_state.identity_loaded) {
        return -1;
    }
    memcpy(out_pubkey, sec_state.id_pub, PUBLIC_KEY_LENGTH);
    return 0;
}

/**
 * Computes a shared secret with a peer using the loaded identity key.
 *
 * @param peer_public_key Peer's public key.
 * @param shared_secret_out Buffer receiving the shared secret.
 * @return 0 on success; -1 for invalid inputs or an unloaded identity, -2 if key exchange fails, or -3 if the resulting secret is all zeros.
 */

int security_compute_shared_secret(const uint8_t* peer_public_key, uint8_t* shared_secret_out) {
    if (!peer_public_key || !shared_secret_out || !sec_state.identity_loaded) {
        return -1;
    }
    if (crypto_scalarmult(shared_secret_out, sec_state.id_priv, peer_public_key) != 0) {
        return -2;
    }
    if (sodium_is_zero(shared_secret_out, SHARED_SECRET_LENGTH)) {
        sodium_memzero(shared_secret_out, SHARED_SECRET_LENGTH);
        return -3;
    }
    return 0;
}

/**
 * Derives a session key from a shared secret and the two peer identifiers.
 *
 * @param shared_secret Shared secret used as the hash input.
 * @param our_id Local node identifier.
 * @param peer_id Remote node identifier.
 * @param session_key_out Buffer receiving the derived session key.
 * @return 0 on success, or -1 if an input or output pointer is null.
 */
int security_derive_session_key(
    const uint8_t* shared_secret, uint16_t our_id, uint16_t peer_id, uint8_t* session_key_out) {
    if (!shared_secret || !session_key_out) {
        return -1;
    }
    uint8_t context[24];
    size_t off = 0;
    memcpy(context + off, &our_id, sizeof(our_id));     off += sizeof(our_id);
    memcpy(context + off, &peer_id, sizeof(peer_id));   off += sizeof(peer_id);
    memcpy(context + off, "MERIDIAN_SESSION_V1", sizeof("MERIDIAN_SESSION_V1") - 1);

    crypto_generichash(session_key_out, SYMMETRIC_KEY_LENGTH,
                       shared_secret, SHARED_SECRET_LENGTH,
                       context, sizeof(context));
    return 0;
}

/**
 * Encrypts plaintext using XChaCha20-Poly1305 with a detached authentication tag.
 *
 * The protocol nonce is expanded into the XChaCha20 nonce using the encryption
 * key and a fixed domain-separation context.
 *
 * @param key Encryption key.
 * @param nonce Protocol nonce used for nonce expansion.
 * @param plaintext Data to encrypt.
 * @param plaintext_len Length of plaintext in bytes.
 * @param aad Additional authenticated data.
 * @param aad_len Length of additional authenticated data in bytes.
 * @param ciphertext_out Buffer receiving the ciphertext.
 * @param tag_out Buffer receiving the detached authentication tag.
 * @return Plaintext length on success, -1 for invalid arguments, or -2 if
 *         encryption fails or produces an unexpected tag length.
 */

int security_encrypt(
    const uint8_t* key,
    const secure_nonce_t* nonce,
    const uint8_t* plaintext,
    size_t plaintext_len,
    const uint8_t* aad,
    size_t aad_len,
    uint8_t* ciphertext_out,
    uint8_t* tag_out) {

    if (!key || !nonce || !plaintext || !ciphertext_out || !tag_out || plaintext_len == 0) {
        return -1;
    }

    /* Derive a full 24-byte XChaCha20 nonce deterministically from our 8-byte protocol nonce.
     * We hash the protocol nonce together with a fixed context tag using BLAKE2b keyed by
     * the symmetric session key to get a unique 16-byte prefix, then append the nonce itself
     * for full 24-byte XChaCha20 extended nonces: [hash(prefix)[..15] | nonce_value(8 bytes)] */
    uint8_t xnonce[24];
    {
        /* Input buffer: nonce_value(8) concatenated with context tag string ("MERIDIAN_XNONCE_V1") */
        uint8_t input_buf[64]; /* plenty of space for combined data */
        size_t in_len = 0;

        memcpy(input_buf + in_len, &nonce->value, sizeof(nonce->value));
        in_len += sizeof(nonce->value);

        const char ctx_str[] = "MERIDIAN_XNONCE_V1";
        size_t ctx_len = sizeof(ctx_str) - 1;
        memcpy(input_buf + in_len, (const uint8_t*)ctx_str, ctx_len);
        in_len += ctx_len;

        uint8_t h[32];
        /* crypto_generichash(out, outlen, msg, msglen, key, keylen) = BLAKE2b keyed hash */
        crypto_generichash(h, sizeof(h), input_buf, in_len, key, SYMMETRIC_KEY_LENGTH);

        memcpy(xnonce, h, 16);              /* bytes 0..15 = hash prefix */
        memcpy(xnonce + 16, &nonce->value, sizeof(nonce->value));  /* bytes 16..23 = protocol nonce */
        sodium_memzero(h, sizeof(h));
    }

    unsigned long long mac_len;
    int r = crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
                ciphertext_out, tag_out, &mac_len,
                plaintext, plaintext_len,
                aad, aad_len,
                NULL, xnonce, key);

    sodium_memzero(xnonce, sizeof(xnonce));

    if (r != 0 || (int)mac_len != TAG_LENGTH) {
        return -2;
    }
    return (int)plaintext_len;
}

/**
 * Decrypts and authenticates ciphertext using the supplied key, nonce, and associated data.
 *
 * @param key Encryption key.
 * @param nonce Protocol nonce used to derive the cipher nonce.
 * @param ciphertext_in Ciphertext to decrypt.
 * @param ciphertext_len Length of the ciphertext in bytes.
 * @param aad Additional authenticated data.
 * @param aad_len Length of the additional authenticated data in bytes.
 * @param tag_in Authentication tag for the ciphertext.
 * @param plaintext_out Buffer for the decrypted plaintext.
 * @return The plaintext length on success, -1 for invalid inputs, or -2 if authentication or decryption fails.
 */
int security_decrypt(
    const uint8_t* key,
    const secure_nonce_t* nonce,
    const uint8_t* ciphertext_in,
    size_t ciphertext_len,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* tag_in,
    uint8_t* plaintext_out) {

    if (!key || !nonce || !ciphertext_in || !tag_in || !plaintext_out || ciphertext_len == 0) {
        return -1;
    }

    /* Derive xnonce the exact same way as security_encrypt */
    uint8_t xnonce[24];
    {
        uint8_t input_buf[64];
        size_t in_len = 0;

        memcpy(input_buf + in_len, &nonce->value, sizeof(nonce->value));
        in_len += sizeof(nonce->value);

        const char ctx_str[] = "MERIDIAN_XNONCE_V1";
        size_t ctx_len = sizeof(ctx_str) - 1;
        memcpy(input_buf + in_len, (const uint8_t*)ctx_str, ctx_len);
        in_len += ctx_len;

        uint8_t h[32];
        crypto_generichash(h, sizeof(h), input_buf, in_len, key, SYMMETRIC_KEY_LENGTH);

        memcpy(xnonce, h, 16);              /* bytes 0..15 = hash prefix */
        memcpy(xnonce + 16, &nonce->value, sizeof(nonce->value));  /* bytes 16..23 = protocol nonce */
        sodium_memzero(h, sizeof(h));
    }

    int r = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
                plaintext_out, NULL,
                ciphertext_in, ciphertext_len,
                tag_in,
                aad, aad_len,
                xnonce, key);

    sodium_memzero(xnonce, sizeof(xnonce));

    if (r != 0) {
        return -2; /* Auth failed or bad inputs */
    }
    return (int)ciphertext_len;
}

/**
 * Generates a protocol nonce using the persistent monotonic counter and randomized low bits.
 *
 * @param out_nonce Destination for the generated nonce.
 * @return 0 on success, or -1 if out_nonce is NULL.
 */

int security_get_next_nonce(secure_nonce_t* out_nonce) {
    if (!out_nonce) {
        return -1;
    }

    sec_state.counter_primary.value++;
    uint64_t mono_part = sec_state.counter_primary.value << NONCE_RANDOM_BITS;
    uint32_t rand_val = randombytes_uniform(1U << NONCE_RANDOM_BITS); /* low 24 bits */
    out_nonce->value = (mono_part & ~((uint64_t)NONCE_RANDOM_MASK)) | (uint64_t)rand_val;

    sec_state.counter_primary.timestamp = platform_get_time_ms();
    compute_counter_hmac(&sec_state.counter_primary, sec_state.counter_primary.hash);

    /* Persist every 1024 increments to reduce flash wear */
    static uint64_t last_persist = 0;
    if (sec_state.counter_primary.value - last_persist >= 1024) {
        platform_flash_write(FLASH_ADDR_COUNTER_PRIMARY, &sec_state.counter_primary,
                             sizeof(monotonic_counter_t));
        last_persist = sec_state.counter_primary.value;
    }

    return 0;
}

/**
 * Stores the identity public key and encrypted private key in persistent flash storage.
 *
 * @param public_key Identity public key to store.
 * @param private_key Identity private key to encrypt and store.
 * @return 0 on success, -1 for invalid inputs, or -2 if private-key encryption fails.
 */

int security_store_identity_keys(const uint8_t* public_key, const uint8_t* private_key) {
    if (!public_key || !private_key) {
        return -1;
    }

    uint8_t nonce_box[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce_box, sizeof(nonce_box));

    uint8_t enc_priv[PRIVATE_KEY_LENGTH + crypto_secretbox_MACBYTES];
    if (crypto_secretbox_easy(enc_priv, private_key, PRIVATE_KEY_LENGTH,
                              nonce_box, sec_state.device_secret) != 0) {
        sodium_memzero(nonce_box, sizeof(nonce_box));
        return -2;
    }

    platform_flash_write(FLASH_ADDR_IDENTITY_KEY, public_key, PUBLIC_KEY_LENGTH);
    platform_flash_write(FLASH_ADDR_IDENTITY_KEY + PUBLIC_KEY_LENGTH, enc_priv, sizeof(enc_priv));
    platform_flash_write(FLASH_ADDR_IDENTITY_KEY + PUBLIC_KEY_LENGTH + sizeof(enc_priv),
                         nonce_box, sizeof(nonce_box));

    sodium_memzero(nonce_box, sizeof(nonce_box));
    sodium_memzero(enc_priv, sizeof(enc_priv));

    memcpy(sec_state.id_pub, public_key, PUBLIC_KEY_LENGTH);
    memcpy(sec_state.id_priv, private_key, PRIVATE_KEY_LENGTH);
    sec_state.identity_loaded = 1;

    return 0;
}

/**
 * Loads the device identity key pair from persistent storage, generating and storing a replacement if no valid key pair is available.
 *
 * @param out_public_key Buffer receiving the public identity key.
 * @param out_private_key Buffer receiving the private identity key.
 * @return 0 on success, or -1 if either output buffer is NULL.
 */
int security_load_identity_keys(uint8_t* out_public_key, uint8_t* out_private_key) {
    if (!out_public_key || !out_private_key) {
        return -1;
    }

    uint8_t pub[PUBLIC_KEY_LENGTH];
    uint8_t enc_priv[PRIVATE_KEY_LENGTH + crypto_secretbox_MACBYTES];
    uint8_t nonce_box[crypto_secretbox_NONCEBYTES];

    platform_flash_read(FLASH_ADDR_IDENTITY_KEY, pub, sizeof(pub));
    platform_flash_read(FLASH_ADDR_IDENTITY_KEY + PUBLIC_KEY_LENGTH, enc_priv, sizeof(enc_priv));
    platform_flash_read(FLASH_ADDR_IDENTITY_KEY + PUBLIC_KEY_LENGTH + sizeof(enc_priv),
                        nonce_box, sizeof(nonce_box));

    /* If all-zeros => no stored key yet */
    if (sodium_is_zero(pub, PUBLIC_KEY_LENGTH) && sodium_is_zero(enc_priv, 4)) {
        uint8_t n_pub[PUBLIC_KEY_LENGTH], n_priv[PRIVATE_KEY_LENGTH];
        crypto_box_keypair(n_pub, n_priv);
        security_store_identity_keys(n_pub, n_priv);
        memcpy(out_public_key, n_pub, PUBLIC_KEY_LENGTH);
        memcpy(out_private_key, n_priv, PRIVATE_KEY_LENGTH);
        return 0;
    }

    uint8_t priv[PRIVATE_KEY_LENGTH];
    if (crypto_secretbox_open_easy(priv, enc_priv, sizeof(enc_priv),
                                   nonce_box, sec_state.device_secret) != 0) {
        /* Decryption failed — regenerate */
        uint8_t n_pub[PUBLIC_KEY_LENGTH], n_priv[PRIVATE_KEY_LENGTH];
        crypto_box_keypair(n_pub, n_priv);
        security_store_identity_keys(n_pub, n_priv);
        memcpy(out_public_key, n_pub, PUBLIC_KEY_LENGTH);
        memcpy(out_private_key, n_priv, PRIVATE_KEY_LENGTH);
        return 0;
    }

    memcpy(out_public_key, pub, PUBLIC_KEY_LENGTH);
    memcpy(out_private_key, priv, PRIVATE_KEY_LENGTH);

    memcpy(sec_state.id_pub, pub, PUBLIC_KEY_LENGTH);
    memcpy(sec_state.id_priv, priv, PRIVATE_KEY_LENGTH);
    sec_state.identity_loaded = 1;

    sodium_memzero(priv, sizeof(priv));
    return 0;
}

/**
 * Stores or replaces a symmetric session key for a peer.
 *
 * @param peer_id Peer identifier associated with the session.
 * @param session_key Symmetric key to store.
 * @return 0 on success, or -1 if the peer identifier is zero or the key is NULL.
 */

int security_set_session(uint16_t peer_id, const uint8_t* session_key) {
    if (!session_key || peer_id == 0) {
        return -1;
    }

    int idx = -1;
    for (int i = 0; i < MAX_ACTIVE_SESSIONS; i++) {
        if (sec_state.sessions[i].peer_id == peer_id) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        for (int i = 0; i < MAX_ACTIVE_SESSIONS; i++) {
            if (!sec_state.sessions[i].active) {
                idx = i;
                break;
            }
        }
    }
    if (idx < 0) {
        /* Table full: evict oldest entry by established_time */
        int evict = 0;
        uint32_t oldest_time = sec_state.sessions[0].established_time;
        for (int i = 1; i < MAX_ACTIVE_SESSIONS; i++) {
            if (!sec_state.sessions[i].active ||
                sec_state.sessions[i].established_time < oldest_time) {
                oldest_time = sec_state.sessions[i].established_time;
                evict = i;
            }
        }
        idx = evict;
    }

    memcpy(sec_state.sessions[idx].session_key, session_key, SYMMETRIC_KEY_LENGTH);
    sec_state.sessions[idx].peer_id = peer_id;
    sec_state.sessions[idx].established_time = platform_get_time_ms();
    sec_state.sessions[idx].active = 1;
    return 0;
}

/**
 * Retrieves an active session key for a peer.
 *
 * @param peer_id Identifier of the peer.
 * @param out_key Buffer that receives the session key.
 * @return 0 on success, -1 if the peer ID is invalid, the output buffer is null, or no session exists, or -2 if the session has expired.
 */
int security_get_session_key(uint16_t peer_id, uint8_t* out_key) {
    if (!out_key || peer_id == 0) {
        return -1;
    }
    for (int i = 0; i < MAX_ACTIVE_SESSIONS; i++) {
        if (sec_state.sessions[i].active && sec_state.sessions[i].peer_id == peer_id) {
            uint32_t now = platform_get_time_ms();
            uint32_t age = (now >= sec_state.sessions[i].established_time) ?
                           (now - sec_state.sessions[i].established_time) : 0;
            if (age > SESSION_TIMEOUT_MS) {
                sec_state.sessions[i].active = 0;
                return -2; /* Expired */
            }
            memcpy(out_key, sec_state.sessions[i].session_key, SYMMETRIC_KEY_LENGTH);
            return 0;
        }
    }
    return -1; /* No session for peer */
}

/**
 * Establishes a pairwise session from a HELLO or RESPONSE handshake message.
 *
 * @param msg Incoming handshake message.
 * @param our_node_id Local node identifier.
 * @param response_out Buffer receiving the handshake response.
 * @return 0 on success; a negative error code if the message, identity, or
 *         shared-secret computation is invalid, or if the message is unsupported.
 */

int security_process_handshake(
    const handshake_message_t* msg, uint16_t our_node_id, handshake_message_t* response_out) {

    if (!msg || !response_out) {
        return -1;
    }
    memset(response_out, 0, sizeof(*response_out));

    /* Protocol v2: uses static identity ECDH (no forward secrecy yet).
     * Flow:
     *   HELLO: initiator sends type=HELLO, initiator_id=I, responder_id=R, public_key = initiator_identity_pub.
     *   RESPONDER branch below: derives session_key via DH(init_priv, initiator_pub), sends back its own identity pub.
     *   INITIATOR branch (on RESPONSE): derives same session_key via DH(our_priv, responder.pub).
     */

    /* We are responder: received HELLO with initiator's identity public key */
    if (msg->type == HANDSHAKE_TYPE_HELLO && msg->responder_id == our_node_id) {
        if (!sec_state.identity_loaded || sodium_is_zero(msg->public_key, PUBLIC_KEY_LENGTH)) {
            return -2;
        }

        uint8_t shared[SHARED_SECRET_LENGTH];
        if (security_compute_shared_secret(msg->public_key, shared) != 0) {
            return -3;
        }

        uint8_t sess_key[SYMMETRIC_KEY_LENGTH];
        security_derive_session_key(shared, msg->initiator_id, our_node_id, sess_key);
        security_set_session(msg->initiator_id, sess_key);
        sodium_memzero(shared, sizeof(shared));
        sodium_memzero(sess_key, sizeof(sess_key));

        response_out->type = HANDSHAKE_TYPE_RESPONSE;
        response_out->initiator_id = msg->initiator_id;
        response_out->responder_id = our_node_id;
        memcpy(response_out->public_key, sec_state.id_pub, PUBLIC_KEY_LENGTH);
        return 0;
    }

    /* We are initiator: received RESPONSE with responder's identity public key */
    if (msg->type == HANDSHAKE_TYPE_RESPONSE && msg->initiator_id == our_node_id) {
        if (!sec_state.identity_loaded || sodium_is_zero(msg->public_key, PUBLIC_KEY_LENGTH)) {
            return -4;
        }

        uint8_t shared[SHARED_SECRET_LENGTH];
        if (security_compute_shared_secret(msg->public_key, shared) != 0) {
            return -5;
        }

        uint8_t sess_key[SYMMETRIC_KEY_LENGTH];
        security_derive_session_key(shared, our_node_id, msg->responder_id, sess_key);
        security_set_session(msg->responder_id, sess_key);
        sodium_memzero(shared, sizeof(shared));
        sodium_memzero(sess_key, sizeof(sess_key));

        response_out->type = HANDSHAKE_TYPE_CONFIRM;
        response_out->initiator_id = our_node_id;
        response_out->responder_id = msg->responder_id;
        return 0;
    }

    return -99; /* Unhandled handshake message type */
}

/**
 * Generates a public/private cryptographic keypair.
 *
 * @param key_type Retained for API compatibility and ignored.
 * @param public_key Buffer receiving the public key.
 * @param private_key Buffer receiving the private key.
 * @return 0 on success, or -1 if an output buffer is null.
 */

int security_generate_keypair(uint8_t key_type, uint8_t* public_key, uint8_t* private_key) {
    if (!public_key || !private_key) return -1;
    (void)key_type;
    crypto_box_keypair(public_key, private_key);
    return 0;
}

/**
 * Derives independent transmission and reception keys from a shared secret.
 *
 * @param shared_secret Shared secret used as the derivation input.
 * @param tx_key Output buffer for the transmission key.
 * @param rx_key Output buffer for the reception key.
 * @return 0 on success, or -1 if an input pointer is NULL.
 */
int security_derive_keys(const uint8_t* shared_secret, uint8_t* tx_key, uint8_t* rx_key) {
    if (!shared_secret || !tx_key || !rx_key) return -1;
    uint8_t tx_ctx[32] = {0}; memcpy(tx_ctx, "MERIDIAN_TX_KEY_V2", 18);
    uint8_t rx_ctx[32] = {0}; memcpy(rx_ctx, "MERIDIAN_RX_KEY_V2", 18);
    crypto_generichash(tx_key, SYMMETRIC_KEY_LENGTH, shared_secret, SHARED_SECRET_LENGTH, tx_ctx, sizeof(tx_ctx));
    crypto_generichash(rx_key, SYMMETRIC_KEY_LENGTH, shared_secret, SHARED_SECRET_LENGTH, rx_ctx, sizeof(rx_ctx));
    return 0;
}

/**
 * Verifies the integrity of the persisted monotonic counter.
 *
 * @return 0 if the counter integrity check succeeds, -1 otherwise.
 */
int security_verify_counter_integrity(void) {
    uint8_t check[32];
    compute_counter_hmac(&sec_state.counter_primary, check);
    return (sodium_memcmp(check, sec_state.counter_primary.hash, 32) == 0) ? 0 : -1;
}

/**
 * Stores the device identity key pair.
 *
 * @param key_type Retained for compatibility and ignored.
 * @param public_key Public identity key to store.
 * @param private_key Private identity key to store.
 * @return The result of storing the identity keys.
 */
int security_store_keys(uint8_t key_type, const uint8_t* public_key, const uint8_t* private_key) {
    (void)key_type;
    return security_store_identity_keys(public_key, private_key);
}

/**
 * Loads the device's persistent identity key pair.
 *
 * @param public_key Buffer receiving the public key.
 * @param private_key Buffer receiving the private key.
 * @return 0 on success; -1 if an output buffer is null or loading fails.
 */
int security_load_keys(uint8_t key_type, uint8_t* public_key, uint8_t* private_key) {
    (void)key_type;
    return security_load_identity_keys(public_key, private_key);
}

/**
 * Stores or updates a symmetric key for a group managed by the specified leader.
 *
 * @param group_id Identifier of the group.
 * @param key_in Group key to store.
 * @param leader_id Identifier of the group leader.
 * @return 0 on success, or -1 if an input is invalid.
 */

int security_set_group_key(uint16_t group_id, const uint8_t* key_in, uint16_t leader_id) {
    if (!key_in || group_id == 0 || leader_id == 0) {
        return -1;
    }

    /* Find existing slot or allocate one */
    int idx = -1;
    for (int i = 0; i < MAX_GROUP_KEYS; i++) {
        if (sec_state.groups[i].group_id == group_id) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        /* Find an empty slot */
        for (int i = 0; i < MAX_GROUP_KEYS; i++) {
            if (!sec_state.groups[i].active) {
                idx = i;
                break;
            }
        }
    }

    if (idx < 0) {
        /* Group table full: evict oldest (highest epoch tiebreak not used for simplicity) */
        uint32_t oldest_epoch = sec_state.groups[0].epoch + 1;
        for (int i = 1; i < MAX_GROUP_KEYS; i++) {
            if (!sec_state.groups[i].active || sec_state.groups[i].epoch < oldest_epoch) {
                oldest_epoch = sec_state.groups[i].epoch;
                idx = i;
            }
        }
    }

    memcpy(sec_state.groups[idx].group_key, key_in, SYMMETRIC_KEY_LENGTH);
    sec_state.groups[idx].group_id  = group_id;
    sec_state.groups[idx].leader_id = (uint8_t)(leader_id & 0xFF); /* For v1, low byte is fine */
    sec_state.groups[idx].epoch     = (sec_state.groups[idx].active ? sec_state.groups[idx].epoch + 1 : 1);
    sec_state.groups[idx].active    = 1;

    return 0;
}

/**
 * Retrieves the symmetric key for an active group membership.
 *
 * @param group_id Identifier of the group.
 * @param out_key Buffer that receives the group key.
 * @return 0 on success, or -1 if the arguments are invalid or no active membership exists.
 */
int security_get_group_key(uint16_t group_id, uint8_t* out_key) {
    if (!out_key || group_id == 0) {
        return -1;
    }

    for (int i = 0; i < MAX_GROUP_KEYS; i++) {
        if (sec_state.groups[i].active && sec_state.groups[i].group_id == group_id) {
            memcpy(out_key, sec_state.groups[i].group_key, SYMMETRIC_KEY_LENGTH);
            return 0;
        }
    }

    return -1; /* Not a member of this group */
}

/**
 * Derives a pairwise secret for encrypted group-join payloads.
 *
 * @param peer_public_key Peer identity public key used for key agreement.
 * @param peer_id Peer identifier used to domain-separate the derived secret.
 * @param shared Buffer receiving the derived pairwise secret.
 * @return 0 on success, or -1 if an input is invalid or key agreement fails.
 */
int security_derive_pairwise_for_peer(
    const uint8_t* peer_public_key,
    uint16_t peer_id,
    uint8_t* shared) {
    if (!peer_public_key || !shared || peer_id == 0) {
        return -1;
    }

    /* Compute ECDH using our identity key and the peer's public key */
    if (security_compute_shared_secret(peer_public_key, shared) != 0) {
        return -1;
    }

    /* Use domain separation with peer_id to derive a pairwise secret suitable for GROUP_JOIN encryption */
    uint8_t context[24];
    size_t off = 0;
    memcpy(context + off, &peer_id, sizeof(peer_id));      off += sizeof(peer_id);
    memcpy(context + off, "MERIDIAN_GROUP_JOIN_V1", sizeof("MERIDIAN_GROUP_JOIN_V1") - 1);

    uint8_t derived[SHARED_SECRET_LENGTH];
    crypto_generichash(derived, SHARED_SECRET_LENGTH, shared, SHARED_SECRET_LENGTH, context, sizeof(context));
    memcpy(shared, derived, SHARED_SECRET_LENGTH);
    sodium_memzero(derived, sizeof(derived));

    return 0;
}
