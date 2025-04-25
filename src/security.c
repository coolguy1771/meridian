#include "security.h"
#include "platform.h"
#include <string.h>
#include <stdlib.h>
#include <sodium.h>

/* Flash storage addresses for monotonic counters */
#define COUNTER_PRIMARY_ADDR 0x10000
#define COUNTER_BACKUP_ADDR 0x20000
#define COUNTER_SECURE_ADDR 0x30000

/* Module state */
static struct
{
    uint8_t mode;
    uint8_t cipher;
    uint8_t node_id[NODE_ID_LENGTH];
    monotonic_counter_t primary_counter;
    monotonic_counter_t backup_counter;
    monotonic_counter_t secure_counter;
    uint8_t device_secret[32]; /* Secret key for counter integrity */
} security_state;

/**
 * Initialize the security subsystem
 */
int security_init(uint8_t mode, uint8_t cipher)
{
    /* Initialize libsodium */
    if (sodium_init() < 0)
    {
        return -1;
    }

    /* Validate parameters */
    if (mode > SECURITY_E2E_AUTH || cipher > CIPHER_CHACHA20_POLY)
    {
        return -1;
    }

    /* Initialize state */
    security_state.mode = mode;
    security_state.cipher = cipher;

    /* Generate a device secret for counter integrity */
    randombytes_buf(security_state.device_secret, sizeof(security_state.device_secret));

    /* Get device ID */
    platform_get_unique_id(security_state.node_id, NODE_ID_LENGTH);

    /* Initialize monotonic counters */
    memset(&security_state.primary_counter, 0, sizeof(monotonic_counter_t));
    memset(&security_state.backup_counter, 0, sizeof(monotonic_counter_t));
    memset(&security_state.secure_counter, 0, sizeof(monotonic_counter_t));

    /* Load counters from storage */
    platform_flash_read(COUNTER_PRIMARY_ADDR, &security_state.primary_counter, sizeof(monotonic_counter_t));
    platform_flash_read(COUNTER_BACKUP_ADDR, &security_state.backup_counter, sizeof(monotonic_counter_t));
    platform_flash_read(COUNTER_SECURE_ADDR, &security_state.secure_counter, sizeof(monotonic_counter_t));

    /* Verify counter integrity */
    return security_verify_counter_integrity();
}

/**
 * Generate a new key pair for this device
 */
int security_generate_keypair(uint8_t key_type, uint8_t *public_key, uint8_t *private_key)
{
    if (!public_key || !private_key)
    {
        return -1;
    }

    if (key_type == KEY_TYPE_IDENTITY || key_type == KEY_TYPE_EPHEMERAL)
    {
        /* For ECC keys used in ECDH, use libsodium's X25519 key generation */
        if (crypto_box_keypair(public_key, private_key) != 0)
        {
            return -2;
        }
    }
    else
    {
        /* For symmetric keys, just fill with random data */
        randombytes_buf(private_key, PRIVATE_KEY_LENGTH);
        randombytes_buf(public_key, PUBLIC_KEY_LENGTH);
    }

    return 0;
}

/**
 * Perform ECDH key exchange to derive a shared secret
 */
int security_compute_shared_secret(
    const uint8_t *peer_public_key,
    const uint8_t *our_private_key,
    uint8_t *shared_secret)
{
    if (!peer_public_key || !our_private_key || !shared_secret)
    {
        return -1;
    }

    /* Use libsodium's X25519 implementation */
    if (crypto_scalarmult(shared_secret, our_private_key, peer_public_key) != 0)
    {
        return -2;
    }

    return 0;
}

/**
 * Derive symmetric keys from a shared secret
 */
int security_derive_keys(
    const uint8_t *shared_secret,
    uint8_t *tx_key,
    uint8_t *rx_key)
{
    if (!shared_secret || !tx_key || !rx_key)
    {
        return -1;
    }

    /* Use libsodium's key derivation function */
    uint8_t master_key[crypto_kdf_KEYBYTES];

    /* Generate master key from shared secret using BLAKE2b */
    crypto_generichash(master_key, sizeof(master_key),
                       shared_secret, SHARED_SECRET_LENGTH,
                       NULL, 0);

    /* Derive TX key - context 1 */
    if (crypto_kdf_derive_from_key(tx_key, SYMMETRIC_KEY_LENGTH,
                                   1, "TX_KEY__",
                                   master_key) != 0)
    {
        return -2;
    }

    /* Derive RX key - context 2 */
    if (crypto_kdf_derive_from_key(rx_key, SYMMETRIC_KEY_LENGTH,
                                   2, "RX_KEY__",
                                   master_key) != 0)
    {
        return -3;
    }

    /* Clear the sensitive master key from memory */
    sodium_memzero(master_key, sizeof(master_key));

    return 0;
}

/**
 * Encrypt a packet using the configured cipher
 */
int security_encrypt(
    const uint8_t *key,
    const secure_nonce_t *nonce,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *associated_data,
    size_t associated_data_len,
    uint8_t *ciphertext,
    uint8_t *tag)
{
    if (!key || !nonce || !plaintext || !ciphertext || !tag)
    {
        return -1;
    }

    /* Prepare nonce as a byte array */
    uint8_t nonce_bytes[NONCE_LENGTH];
    memcpy(nonce_bytes, nonce->node_id, sizeof(nonce->node_id));
    memcpy(nonce_bytes + sizeof(nonce->node_id), &nonce->counter, sizeof(nonce->counter));
    nonce_bytes[NONCE_LENGTH - 1] = nonce->random;

    /* Use the appropriate cipher */
    if (security_state.cipher == CIPHER_AES_GCM)
    {
        /* Initialize with all-zero bytes so it's safe to use without checking libsodium init */
        crypto_aead_aes256gcm_state state;
        memset(&state, 0, sizeof(state));

        /* Initialize AES-GCM state */
        if (crypto_aead_aes256gcm_beforenm(&state, key) != 0)
        {
            return -2;
        }

        unsigned long long ciphertext_len_long = 0;

        /* Encrypt and authenticate data */
        if (crypto_aead_aes256gcm_encrypt_detached_afternm(
                ciphertext,
                tag, NULL,
                plaintext, plaintext_len,
                associated_data, associated_data_len,
                NULL, /* No additional nonce */
                nonce_bytes,
                &state) != 0)
        {
            return -3;
        }

        return plaintext_len;
    }
    else /* CIPHER_CHACHA20_POLY */
    {
        unsigned long long ciphertext_len_long = 0;
        unsigned long long tag_len_long = crypto_aead_chacha20poly1305_ABYTES;

        /* Encrypt using ChaCha20-Poly1305 */
        if (crypto_aead_chacha20poly1305_ietf_encrypt_detached(
                ciphertext,
                tag, NULL,
                plaintext, plaintext_len,
                associated_data, associated_data_len,
                NULL, /* No additional nonce */
                nonce_bytes,
                key) != 0)
        {
            return -3;
        }

        return plaintext_len;
    }
}

/**
 * Decrypt a packet using the configured cipher
 */
int security_decrypt(
    const uint8_t *key,
    const secure_nonce_t *nonce,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *associated_data,
    size_t associated_data_len,
    const uint8_t *tag,
    uint8_t *plaintext)
{
    if (!key || !nonce || !ciphertext || !plaintext || !tag)
    {
        return -1;
    }

    /* Prepare nonce as a byte array */
    uint8_t nonce_bytes[NONCE_LENGTH];
    memcpy(nonce_bytes, nonce->node_id, sizeof(nonce->node_id));
    memcpy(nonce_bytes + sizeof(nonce->node_id), &nonce->counter, sizeof(nonce->counter));
    nonce_bytes[NONCE_LENGTH - 1] = nonce->random;

    /* Use the appropriate cipher */
    if (security_state.cipher == CIPHER_AES_GCM)
    {
        /* Initialize with all-zero bytes so it's safe to use without checking libsodium init */
        crypto_aead_aes256gcm_state state;
        memset(&state, 0, sizeof(state));

        /* Initialize AES-GCM state */
        if (crypto_aead_aes256gcm_beforenm(&state, key) != 0)
        {
            return -2;
        }

        /* Decrypt and verify data */
        if (crypto_aead_aes256gcm_decrypt_detached_afternm(
                plaintext,
                NULL,
                ciphertext, ciphertext_len,
                tag,
                associated_data, associated_data_len,
                nonce_bytes,
                &state) != 0)
        {
            return -3; /* Authentication failed */
        }

        return ciphertext_len;
    }
    else /* CIPHER_CHACHA20_POLY */
    {
        /* Decrypt using ChaCha20-Poly1305 */
        if (crypto_aead_chacha20poly1305_ietf_decrypt_detached(
                plaintext,
                NULL,
                ciphertext, ciphertext_len,
                tag,
                associated_data, associated_data_len,
                nonce_bytes,
                key) != 0)
        {
            return -3; /* Authentication failed */
        }

        return ciphertext_len;
    }
}

/**
 * Get the next nonce for a transmission
 */
int security_get_next_nonce(secure_nonce_t *nonce)
{
    if (!nonce)
    {
        return -1;
    }

    /* Use device ID for node_id */
    memcpy(nonce->node_id, security_state.node_id, NODE_ID_LENGTH);

    /* Set counter from primary counter */
    nonce->counter = security_state.primary_counter.value++;

    /* Generate random byte */
    randombytes_buf(&nonce->random, 1);

    /* Update counter hash using HMAC-SHA256 with device secret as key */
    crypto_auth_hmacsha256_state hmac_state;
    crypto_auth_hmacsha256_init(&hmac_state, security_state.device_secret, sizeof(security_state.device_secret));
    crypto_auth_hmacsha256_update(&hmac_state, (const uint8_t *)&security_state.primary_counter.value, sizeof(uint64_t));
    crypto_auth_hmacsha256_final(&hmac_state, security_state.primary_counter.hash);

    /* Update timestamp */
    security_state.primary_counter.timestamp = platform_get_time_ms();
    security_state.primary_counter.valid = 1;

    /* Periodically save to flash */
    platform_flash_write(COUNTER_PRIMARY_ADDR, &security_state.primary_counter, sizeof(monotonic_counter_t));

    /* Update backup if it's significantly behind */
    if (security_state.primary_counter.value - security_state.backup_counter.value > 1000)
    {
        security_state.backup_counter = security_state.primary_counter;
        platform_flash_write(COUNTER_BACKUP_ADDR, &security_state.backup_counter, sizeof(monotonic_counter_t));
    }

    /* Update secure element counter (high bits only) */
    uint32_t high_bits = (uint32_t)(security_state.primary_counter.value >> 32);
    if (high_bits > (uint32_t)(security_state.secure_counter.value >> 32))
    {
        security_state.secure_counter.value = security_state.primary_counter.value;
        security_state.secure_counter.timestamp = security_state.primary_counter.timestamp;
        security_state.secure_counter.valid = 1;

        /* Update hash */
        crypto_auth_hmacsha256_state hmac_state;
        crypto_auth_hmacsha256_init(&hmac_state, security_state.device_secret, sizeof(security_state.device_secret));
        crypto_auth_hmacsha256_update(&hmac_state, (const uint8_t *)&security_state.secure_counter.value, sizeof(uint64_t));
        crypto_auth_hmacsha256_final(&hmac_state, security_state.secure_counter.hash);

        platform_flash_write(COUNTER_SECURE_ADDR, &security_state.secure_counter, sizeof(monotonic_counter_t));
    }

    return 0;
}

/**
 * Verify the integrity of the monotonic counter system
 */
int security_verify_counter_integrity(void)
{
    /* Verify hash of primary counter */
    uint8_t expected_hash[32];
    int primary_valid = 0, backup_valid = 0, secure_valid = 0;

    /* Check primary counter */
    if (security_state.primary_counter.valid)
    {
        crypto_auth_hmacsha256_state hmac_state;
        crypto_auth_hmacsha256_init(&hmac_state, security_state.device_secret, sizeof(security_state.device_secret));
        crypto_auth_hmacsha256_update(&hmac_state, (const uint8_t *)&security_state.primary_counter.value, sizeof(uint64_t));
        crypto_auth_hmacsha256_final(&hmac_state, expected_hash);

        primary_valid = memcmp(expected_hash, security_state.primary_counter.hash, 32) == 0;
    }

    /* Check backup counter */
    if (security_state.backup_counter.valid)
    {
        crypto_auth_hmacsha256_state hmac_state;
        crypto_auth_hmacsha256_init(&hmac_state, security_state.device_secret, sizeof(security_state.device_secret));
        crypto_auth_hmacsha256_update(&hmac_state, (const uint8_t *)&security_state.backup_counter.value, sizeof(uint64_t));
        crypto_auth_hmacsha256_final(&hmac_state, expected_hash);

        backup_valid = memcmp(expected_hash, security_state.backup_counter.hash, 32) == 0;
    }

    /* Check secure element counter */
    if (security_state.secure_counter.valid)
    {
        crypto_auth_hmacsha256_state hmac_state;
        crypto_auth_hmacsha256_init(&hmac_state, security_state.device_secret, sizeof(security_state.device_secret));
        crypto_auth_hmacsha256_update(&hmac_state, (const uint8_t *)&security_state.secure_counter.value, sizeof(uint64_t));
        crypto_auth_hmacsha256_final(&hmac_state, expected_hash);

        secure_valid = memcmp(expected_hash, security_state.secure_counter.hash, 32) == 0;
    }

    /* Determine the correct counter through voting and validation */
    if (primary_valid && backup_valid && security_state.primary_counter.value == security_state.backup_counter.value)
    {
        /* Both primary and backup are valid and match */
        return 0;
    }
    else if (primary_valid && secure_valid &&
             (security_state.primary_counter.value >> 32) == (security_state.secure_counter.value >> 32))
    {
        /* Primary and secure element high bits match */
        return 0;
    }
    else if (backup_valid && secure_valid &&
             (security_state.backup_counter.value >> 32) == (security_state.secure_counter.value >> 32))
    {
        /* Backup and secure element high bits match */
        security_state.primary_counter = security_state.backup_counter;
        platform_flash_write(COUNTER_PRIMARY_ADDR, &security_state.primary_counter, sizeof(monotonic_counter_t));
        return 0;
    }
    else if (primary_valid && backup_valid && secure_valid)
    {
        /* All valid but different - use highest value */
        uint64_t max_value = security_state.primary_counter.value;
        if (security_state.backup_counter.value > max_value)
        {
            max_value = security_state.backup_counter.value;
        }
        if (security_state.secure_counter.value > max_value)
        {
            max_value = security_state.secure_counter.value;
        }

        security_state.primary_counter.value = max_value;
        security_state.primary_counter.timestamp = platform_get_time_ms();

        /* Update hash */
        crypto_auth_hmacsha256_state hmac_state;
        crypto_auth_hmacsha256_init(&hmac_state, security_state.device_secret, sizeof(security_state.device_secret));
        crypto_auth_hmacsha256_update(&hmac_state, (const uint8_t *)&security_state.primary_counter.value, sizeof(uint64_t));
        crypto_auth_hmacsha256_final(&hmac_state, security_state.primary_counter.hash);

        platform_flash_write(COUNTER_PRIMARY_ADDR, &security_state.primary_counter, sizeof(monotonic_counter_t));

        /* Update backup too */
        security_state.backup_counter = security_state.primary_counter;
        platform_flash_write(COUNTER_BACKUP_ADDR, &security_state.backup_counter, sizeof(monotonic_counter_t));

        return 0;
    }
    else if (primary_valid)
    {
        /* Only primary is valid */
        return 0;
    }
    else if (backup_valid)
    {
        /* Only backup is valid */
        security_state.primary_counter = security_state.backup_counter;
        platform_flash_write(COUNTER_PRIMARY_ADDR, &security_state.primary_counter, sizeof(monotonic_counter_t));
        return 0;
    }
    else if (secure_valid)
    {
        /* Only secure element is valid - reconstruct from high bits */
        security_state.primary_counter.value = security_state.secure_counter.value;
        security_state.primary_counter.timestamp = platform_get_time_ms();
        security_state.primary_counter.valid = 1;

        /* Update hash */
        crypto_auth_hmacsha256_state hmac_state;
        crypto_auth_hmacsha256_init(&hmac_state, security_state.device_secret, sizeof(security_state.device_secret));
        crypto_auth_hmacsha256_update(&hmac_state, (const uint8_t *)&security_state.primary_counter.value, sizeof(uint64_t));
        crypto_auth_hmacsha256_final(&hmac_state, security_state.primary_counter.hash);

        platform_flash_write(COUNTER_PRIMARY_ADDR, &security_state.primary_counter, sizeof(monotonic_counter_t));

        return 0;
    }
    else
    {
        /* All verification failed - potential tampering */
        /* For now, initialize with a new counter */
        security_state.primary_counter.value = 1000000; /* Start with a large safety margin */
        security_state.primary_counter.timestamp = platform_get_time_ms();
        security_state.primary_counter.valid = 1;

        /* Update hash */
        crypto_auth_hmacsha256_state hmac_state;
        crypto_auth_hmacsha256_init(&hmac_state, security_state.device_secret, sizeof(security_state.device_secret));
        crypto_auth_hmacsha256_update(&hmac_state, (const uint8_t *)&security_state.primary_counter.value, sizeof(uint64_t));
        crypto_auth_hmacsha256_final(&hmac_state, security_state.primary_counter.hash);

        platform_flash_write(COUNTER_PRIMARY_ADDR, &security_state.primary_counter, sizeof(monotonic_counter_t));

        /* Initialize backup too */
        security_state.backup_counter = security_state.primary_counter;
        platform_flash_write(COUNTER_BACKUP_ADDR, &security_state.backup_counter, sizeof(monotonic_counter_t));

        /* Initialize secure element counter */
        security_state.secure_counter = security_state.primary_counter;
        platform_flash_write(COUNTER_SECURE_ADDR, &security_state.secure_counter, sizeof(monotonic_counter_t));

        return 0;
    }
}

/**
 * Store public and private keys to persistent storage
 */
int security_store_keys(
    uint8_t key_type,
    const uint8_t *public_key,
    const uint8_t *private_key)
{
    if (!public_key || !private_key)
    {
        return -1;
    }

    /* Different key types are stored at different flash locations */
    uint32_t base_addr;
    switch (key_type)
    {
    case KEY_TYPE_IDENTITY:
        base_addr = 0x40000;
        break;
    case KEY_TYPE_EPHEMERAL:
        base_addr = 0x41000;
        break;
    case KEY_TYPE_SYMMETRIC:
        base_addr = 0x42000;
        break;
    case KEY_TYPE_TX:
        base_addr = 0x43000;
        break;
    case KEY_TYPE_RX:
        base_addr = 0x44000;
        break;
    default:
        return -2;
    }

    /* Use authenticated encryption with device secret as key to protect the private key */
    uint8_t encrypted_private[PRIVATE_KEY_LENGTH + crypto_secretbox_MACBYTES];
    uint8_t nonce[crypto_secretbox_NONCEBYTES];

    /* Generate nonce */
    randombytes_buf(nonce, sizeof(nonce));

    /* Encrypt private key */
    if (crypto_secretbox_easy(encrypted_private, private_key, PRIVATE_KEY_LENGTH,
                              nonce, security_state.device_secret) != 0)
    {
        return -3;
    }

    /* Calculate a checksum using HMAC-SHA256 */
    uint8_t checksum[32];
    crypto_auth_hmacsha256(checksum, public_key, PUBLIC_KEY_LENGTH, security_state.device_secret);

    /* Save public key, encrypted private key, nonce, and checksum */
    platform_flash_write(base_addr, public_key, PUBLIC_KEY_LENGTH);
    platform_flash_write(base_addr + PUBLIC_KEY_LENGTH, encrypted_private, sizeof(encrypted_private));
    platform_flash_write(base_addr + PUBLIC_KEY_LENGTH + sizeof(encrypted_private), nonce, sizeof(nonce));
    platform_flash_write(base_addr + PUBLIC_KEY_LENGTH + sizeof(encrypted_private) + sizeof(nonce), checksum, sizeof(checksum));

    return 0;
}

/**
 * Load public and private keys from persistent storage
 */
int security_load_keys(
    uint8_t key_type,
    uint8_t *public_key,
    uint8_t *private_key)
{
    if (!public_key || !private_key)
    {
        return -1;
    }

    /* Different key types are stored at different flash locations */
    uint32_t base_addr;
    switch (key_type)
    {
    case KEY_TYPE_IDENTITY:
        base_addr = 0x40000;
        break;
    case KEY_TYPE_EPHEMERAL:
        base_addr = 0x41000;
        break;
    case KEY_TYPE_SYMMETRIC:
        base_addr = 0x42000;
        break;
    case KEY_TYPE_TX:
        base_addr = 0x43000;
        break;
    case KEY_TYPE_RX:
        base_addr = 0x44000;
        break;
    default:
        return -2;
    }

    /* Read public key, encrypted private key, nonce, and checksum */
    uint8_t stored_public[PUBLIC_KEY_LENGTH];
    uint8_t encrypted_private[PRIVATE_KEY_LENGTH + crypto_secretbox_MACBYTES];
    uint8_t nonce[crypto_secretbox_NONCEBYTES];
    uint8_t stored_checksum[32];

    platform_flash_read(base_addr, stored_public, PUBLIC_KEY_LENGTH);
    platform_flash_read(base_addr + PUBLIC_KEY_LENGTH, encrypted_private, sizeof(encrypted_private));
    platform_flash_read(base_addr + PUBLIC_KEY_LENGTH + sizeof(encrypted_private), nonce, sizeof(nonce));
    platform_flash_read(base_addr + PUBLIC_KEY_LENGTH + sizeof(encrypted_private) + sizeof(nonce), stored_checksum, sizeof(stored_checksum));

    /* Verify checksum */
    uint8_t calculated_checksum[32];
    crypto_auth_hmacsha256(calculated_checksum, stored_public, PUBLIC_KEY_LENGTH, security_state.device_secret);

    if (memcmp(stored_checksum, calculated_checksum, 32) != 0)
    {
        /* Checksum mismatch - keys might be corrupted or not initialized */
        /* Generate a new keypair instead */
        return security_generate_keypair(key_type, public_key, private_key);
    }

    /* Decrypt the private key */
    if (crypto_secretbox_open_easy(private_key, encrypted_private, sizeof(encrypted_private),
                                   nonce, security_state.device_secret) != 0)
    {
        /* Decryption failed, generate a new keypair */
        return security_generate_keypair(key_type, public_key, private_key);
    }

    /* Copy the public key */
    memcpy(public_key, stored_public, PUBLIC_KEY_LENGTH);

    return 0;
}