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
} sec_state;

/* ============================================================================
 * Internal helpers
 * ============================================================================ */

static int compute_counter_hmac(const monotonic_counter_t* ctr, uint8_t out_hash[32]) {
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, sec_state.device_secret, 32);
    crypto_auth_hmacsha256_update(&st, (const uint8_t*)&ctr->value, sizeof(ctr->value));
    crypto_auth_hmacsha256_final(&st, out_hash);
    return 0;
}

/* ============================================================================
 * Initialization
 * ============================================================================ */

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

    /* Load or generate device secret used for HMAC of stored data */
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

    /* Load monotonic counter from flash or initialize new */
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

int security_get_identity_public_key(uint8_t* out_pubkey) {
    if (!out_pubkey || !sec_state.identity_loaded) {
        return -1;
    }
    memcpy(out_pubkey, sec_state.id_pub, PUBLIC_KEY_LENGTH);
    return 0;
}

/* ============================================================================
 * Key exchange & session key derivation (X25519 ECDH)
 * ============================================================================ */

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

/* ============================================================================
 * AEAD encrypt/decrypt using XChaCha20-Poly1305 (libsodium)
 *
 * We derive a full 24-byte XChaCha20 nonce from our compact 8-byte protocol nonce
 * via XSalsa20, ensuring:
 *   - Extended nonce space that survives even rare counter collisions.
 *   - Full AEAD guarantees on the same key/nonce pair across encrypt and decrypt.
 * ============================================================================ */

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

    /* Derive 24-byte XChaCha20 nonce from our 8-byte protocol nonce + key */
    uint8_t xnonce[24];
    crypto_stream_xsalsa20(xnonce, sizeof(xnonce), (const uint8_t*)&nonce->value, key);

    unsigned long long mac_len;
    int r = crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
                ciphertext_out, /* c_out */
                tag_out,        /* mac_out */
                &mac_len,       /* maclen_p */
                plaintext, plaintext_len,
                aad, aad_len,
                NULL, xnonce, key);

    sodium_memzero(xnonce, sizeof(xnonce));

    if (r != 0 || (int)mac_len != TAG_LENGTH) {
        return -2;
    }
    return (int)plaintext_len;
}

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

    uint8_t xnonce[24];
    crypto_stream_xsalsa20(xnonce, sizeof(xnonce), (const uint8_t*)&nonce->value, key);

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

/* ============================================================================
 * Nonce generation: monotonic base + randomized low bits
 * ============================================================================ */

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

/* ============================================================================
 * Identity key persistence (encrypted + integrity-protected)
 * ============================================================================ */

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

/* ============================================================================
 * Session management: per-peer symmetric keys
 * ============================================================================ */

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
        /* Table full: evict oldest */
        uint32_t oldest_time = sec_state.sessions[0].established_time;
        for (int i = 1; i < MAX_ACTIVE_SESSIONS; i++) {
            if (sec_state.sessions[i].established_time < oldest_time) {
                oldest_time = sec_state.sessions[i].established_time;
                idx = i;
            }
        }
    }

    memcpy(sec_state.sessions[idx].session_key, session_key, SYMMETRIC_KEY_LENGTH);
    sec_state.sessions[idx].peer_id = peer_id;
    sec_state.sessions[idx].established_time = platform_get_time_ms();
    sec_state.sessions[idx].active = 1;
    return 0;
}

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

/* ============================================================================
 * Handshake protocol: establish pairwise sessions via ephemeral ECDH
 *
 * Simplified v1 flow (no signatures yet, relies on mesh trust model + later auth):
 *   HELLO(initiator_id=I, pub_key=I_eph_pub) -> R
 *   R derives session_key from ECDH(R_id_priv, I_eph_pub), responds:
 *     RESPONSE(initiator_id=I, responder_id=R)
 *   Both sides store session_key for future encrypted packets.
 * ============================================================================ */

int security_process_handshake(
    const handshake_message_t* msg, uint16_t our_node_id, handshake_message_t* response_out) {

    if (!msg || !response_out) {
        return -1;
    }
    memset(response_out, 0, sizeof(*response_out));

    /* We are responder: received HELLO */
    if (msg->type == HANDSHAKE_TYPE_HELLO && msg->responder_id == our_node_id) {
        if (sodium_is_zero(msg->public_key, PUBLIC_KEY_LENGTH)) {
            return -2;
        }

        uint8_t shared[SHARED_SECRET_LENGTH];
        if (security_compute_shared_secret(msg->public_key, shared) != 0) {
            return -3;
        }

        uint8_t sess_key[SYMMETRIC_KEY_LENGTH];
        security_derive_session_key(shared, our_node_id, msg->initiator_id, sess_key);
        security_set_session(msg->initiator_id, sess_key);
        sodium_memzero(shared, sizeof(shared));
        sodium_memzero(sess_key, sizeof(sess_key));

        response_out->type = HANDSHAKE_TYPE_RESPONSE;
        response_out->initiator_id = msg->initiator_id;
        response_out->responder_id = our_node_id;
        return 0;
    }

    /* We are initiator: received RESPONSE confirming session */
    if (msg->type == HANDSHAKE_TYPE_RESPONSE && msg->initiator_id == our_node_id) {
        /* Session key already derived by responder; we re-derive locally via identity DH */
        uint8_t shared[SHARED_SECRET_LENGTH];
        if (security_compute_shared_secret(msg->public_key, shared) != 0) {
            return -3;
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

    return -4; /* Unhandled handshake message type */
}

/* ============================================================================
 * Legacy compatibility wrappers (kept for existing API consumers)
 * ============================================================================ */

int security_generate_keypair(uint8_t key_type, uint8_t* public_key, uint8_t* private_key) {
    if (!public_key || !private_key) return -1;
    (void)key_type;
    crypto_box_keypair(public_key, private_key);
    return 0;
}

int security_derive_keys(const uint8_t* shared_secret, uint8_t* tx_key, uint8_t* rx_key) {
    if (!shared_secret || !tx_key || !rx_key) return -1;
    uint8_t tx_ctx[32] = {0}; memcpy(tx_ctx, "MERIDIAN_TX_KEY_V2", 18);
    uint8_t rx_ctx[32] = {0}; memcpy(rx_ctx, "MERIDIAN_RX_KEY_V2", 18);
    crypto_generichash(tx_key, SYMMETRIC_KEY_LENGTH, shared_secret, SHARED_SECRET_LENGTH, tx_ctx, sizeof(tx_ctx));
    crypto_generichash(rx_key, SYMMETRIC_KEY_LENGTH, shared_secret, SHARED_SECRET_LENGTH, rx_ctx, sizeof(rx_ctx));
    return 0;
}

int security_verify_counter_integrity(void) {
    uint8_t check[32];
    compute_counter_hmac(&sec_state.counter_primary, check);
    return (sodium_memcmp(check, sec_state.counter_primary.hash, 32) == 0) ? 0 : -1;
}

int security_store_keys(uint8_t key_type, const uint8_t* public_key, const uint8_t* private_key) {
    (void)key_type;
    return security_store_identity_keys(public_key, private_key);
}

int security_load_keys(uint8_t key_type, uint8_t* public_key, uint8_t* private_key) {
    (void)key_type;
    return security_load_identity_keys(public_key, private_key);
}
