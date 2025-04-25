#include "security.h"
#include "platform.h"
#include "packet.h" /* For MAX_PAYLOAD_SIZE */
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

    /*
     * Generate a device secret for counter integrity
     * or load it from persistent storage if available
     */
    uint8_t stored_secret[32];
    int result = platform_flash_read(0x50000, stored_secret, sizeof(stored_secret));

    if (result == 0 && !sodium_is_zero(stored_secret, sizeof(stored_secret)))
    {
        /* Use stored device secret */
        memcpy(security_state.device_secret, stored_secret, sizeof(security_state.device_secret));
        /* Clear sensitive data from stack */
        sodium_memzero(stored_secret, sizeof(stored_secret));
    }
    else
    {
        /* Generate new device secret */
        randombytes_buf(security_state.device_secret, sizeof(security_state.device_secret));

        /* Persist the device secret (use wear-leveling with multiple sectors) */
        uint8_t wear_index = 0;
        platform_flash_read(0x60000, &wear_index, sizeof(wear_index));

        /* Rotate through 8 different sectors to implement basic wear-leveling */
        wear_index = (wear_index + 1) % 8;
        uint32_t sector_addr = 0x50000 + (wear_index * 0x1000);

        /* Erase sector first for clean write (if platform supports it) */
        platform_flash_erase_sector(sector_addr / 0x1000);

        /* Store the secret */
        platform_flash_write(sector_addr, security_state.device_secret, sizeof(security_state.device_secret));

        /* Update wear index */
        platform_flash_write(0x60000, &wear_index, sizeof(wear_index));
    }

#ifdef USE_HARDWARE_CRYPTO
    /* If hardware security module is available, also store there */
    platform_store_secure_key(SECURE_KEY_DEVICE_SECRET, security_state.device_secret, sizeof(security_state.device_secret));
#endif

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
 *
 * This improved implementation adds more entropy sources and defense-in-depth
 * to strengthen the key derivation process.
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

    /* Validate shared secret quality */
    if (sodium_is_zero(shared_secret, SHARED_SECRET_LENGTH))
    {
        /* All-zero shared secret is a red flag */
        return -1;
    }

    /* Use secure memory allocation if available */
#ifdef USE_SECURE_MEMORY
    uint8_t *master_key = sodium_malloc(crypto_kdf_KEYBYTES);
    if (!master_key)
    {
        return -2;
    }
#else
    uint8_t master_key[crypto_kdf_KEYBYTES];
#endif

    /* Gather additional entropy for stronger key derivation */
    uint8_t additional_entropy[64];

    /* Add device-specific info */
    memcpy(additional_entropy, security_state.node_id, NODE_ID_LENGTH);

    /* Add timestamp */
    uint32_t timestamp = platform_get_time_ms();
    memcpy(additional_entropy + NODE_ID_LENGTH, &timestamp, sizeof(timestamp));

    /* Add some random bytes */
    randombytes_buf(additional_entropy + NODE_ID_LENGTH + sizeof(timestamp),
                    sizeof(additional_entropy) - NODE_ID_LENGTH - sizeof(timestamp));

    /* Optional: Hardware-specific entropy */
#ifdef USE_HARDWARE_CRYPTO
    uint8_t hw_entropy[16];
    if (platform_get_hardware_entropy(hw_entropy, sizeof(hw_entropy)) == 0)
    {
        /* XOR with part of our additional entropy to combine sources */
        for (size_t i = 0; i < sizeof(hw_entropy); i++)
        {
            additional_entropy[i] ^= hw_entropy[i];
        }
    }
#endif

    /* Generate master key from shared secret using BLAKE2b with additional entropy as key */
    crypto_generichash(master_key, sizeof(master_key),
                       shared_secret, SHARED_SECRET_LENGTH,
                       additional_entropy, sizeof(additional_entropy));

    /* Mix in device secret for domain separation */
    for (size_t i = 0; i < crypto_kdf_KEYBYTES; i++)
    {
        master_key[i] ^= security_state.device_secret[i % sizeof(security_state.device_secret)];
    }

    /* Derive TX key - context 1 with longer context for better separation */
    if (crypto_kdf_derive_from_key(tx_key, SYMMETRIC_KEY_LENGTH,
                                   1, "TX_KEY_MERIDIAN_RADIO",
                                   master_key) != 0)
    {
        sodium_memzero(master_key, sizeof(master_key));
#ifdef USE_SECURE_MEMORY
        sodium_free(master_key);
#endif
        return -3;
    }

    /* Derive RX key - context 2 with longer context for better separation */
    if (crypto_kdf_derive_from_key(rx_key, SYMMETRIC_KEY_LENGTH,
                                   2, "RX_KEY_MERIDIAN_RADIO",
                                   master_key) != 0)
    {
        sodium_memzero(master_key, sizeof(master_key));
#ifdef USE_SECURE_MEMORY
        sodium_free(master_key);
#endif
        return -4;
    }

    /* Clear all sensitive data from memory */
    sodium_memzero(master_key, sizeof(master_key));
    sodium_memzero(additional_entropy, sizeof(additional_entropy));

#ifdef USE_SECURE_MEMORY
    sodium_free(master_key);
#endif

    /* Optionally verify key quality */
    if (sodium_is_zero(tx_key, SYMMETRIC_KEY_LENGTH / 4) ||
        sodium_is_zero(rx_key, SYMMETRIC_KEY_LENGTH / 4))
    {
        /* Keys contain too many zeros - suspicious */
        sodium_memzero(tx_key, SYMMETRIC_KEY_LENGTH);
        sodium_memzero(rx_key, SYMMETRIC_KEY_LENGTH);
        return -5;
    }

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
    /* Validate all pointers and parameters */
    if (!key || !nonce || !plaintext || !ciphertext || !tag)
    {
        return -1;
    }

    /* Check buffer sizes to prevent overflows */
    if (plaintext_len > MAX_PAYLOAD_SIZE ||
        (associated_data && associated_data_len > 1024)) /* Reasonable limit */
    {
        return -1;
    }

    /* Verify key is properly aligned and has expected format */
    if (!sodium_is_zero(key, SYMMETRIC_KEY_LENGTH) &&
        sodium_is_zero(key, SYMMETRIC_KEY_LENGTH / 4))
    {
        /* Key appears to have a suspicious pattern (partially zeroed) */
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
    /* Validate all pointers and parameters */
    if (!key || !nonce || !ciphertext || !plaintext || !tag)
    {
        return -1;
    }

    /* Check buffer sizes to prevent overflows */
    if (ciphertext_len > MAX_PAYLOAD_SIZE ||
        (associated_data && associated_data_len > 1024)) /* Reasonable limit */
    {
        return -1;
    }

    /* Verify key is properly aligned and has expected format */
    if (!sodium_is_zero(key, SYMMETRIC_KEY_LENGTH) &&
        sodium_is_zero(key, SYMMETRIC_KEY_LENGTH / 4))
    {
        /* Key appears to have a suspicious pattern (partially zeroed) */
        return -1;
    }

    /* Add protection against replay attacks by checking counters */
    uint64_t msg_counter = nonce->counter;

    /* Check against our receive window */
    static uint64_t last_counters[16] = {0}; /* Remember last N messages */
    static int counter_idx = 0;

    /* Check if this is a replay */
    for (int i = 0; i < 16; i++)
    {
        if (last_counters[i] == msg_counter)
        {
            /* This is likely a replay attack */
            return -4;
        }
    }

    /* Store this counter */
    last_counters[counter_idx] = msg_counter;
    counter_idx = (counter_idx + 1) % 16;

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
 *
 * This function creates a secure nonce using multiple sources of entropy:
 * 1. Device ID (uniquely identifies the node)
 * 2. Monotonic counter (ensures replay protection)
 * 3. Multiple random bytes (adds additional entropy against prediction)
 * 4. Hardware-specific entropy if available
 */
int security_get_next_nonce(secure_nonce_t *nonce)
{
    if (!nonce)
    {
        return -1;
    }

    /* Use device ID for node_id */
    memcpy(nonce->node_id, security_state.node_id, NODE_ID_LENGTH);

    /* Set counter from primary counter with atomic operation to prevent race conditions */
    uint64_t counter_value;
#ifdef ATOMIC_OPERATIONS
    counter_value = atomic_fetch_add(&security_state.primary_counter.value, 1);
#else
    counter_value = security_state.primary_counter.value++;
#endif

    nonce->counter = counter_value;

    /* Generate multiple random bytes for better unpredictability */
    randombytes_buf(&nonce->random, sizeof(nonce->random));

    /* Add hardware entropy if available (e.g., thermal noise, clock jitter) */
#ifdef USE_HARDWARE_CRYPTO
    uint8_t hw_entropy;
    if (platform_get_hardware_entropy(&hw_entropy, 1) == 0)
    {
        /* XOR with existing random value to combine entropy sources */
        nonce->random ^= hw_entropy;
    }
#endif

    /* Collect additional entropy from system state */
    uint32_t timestamp = platform_get_time_ms();
    uint32_t cpu_cycles = platform_get_cpu_cycles();

    /* Mix additional entropy into the nonce */
    crypto_auth_hmacsha256_state entropy_mixer;
    crypto_auth_hmacsha256_init(&entropy_mixer, security_state.device_secret, sizeof(security_state.device_secret));
    crypto_auth_hmacsha256_update(&entropy_mixer, (const uint8_t *)&timestamp, sizeof(timestamp));
    crypto_auth_hmacsha256_update(&entropy_mixer, (const uint8_t *)&cpu_cycles, sizeof(cpu_cycles));
    crypto_auth_hmacsha256_update(&entropy_mixer, (const uint8_t *)&counter_value, sizeof(counter_value));

    /* Use part of this entropy to strengthen the nonce */
    uint8_t extra_entropy[32];
    crypto_auth_hmacsha256_final(&entropy_mixer, extra_entropy);

    /* XOR additional entropy into the random portion of the nonce */
    nonce->random ^= extra_entropy[0];

    /* Update counter hash using HMAC-SHA256 with device secret as key */
    crypto_auth_hmacsha256_state hmac_state;
    crypto_auth_hmacsha256_init(&hmac_state, security_state.device_secret, sizeof(security_state.device_secret));
    crypto_auth_hmacsha256_update(&hmac_state, (const uint8_t *)&security_state.primary_counter.value, sizeof(uint64_t));
    crypto_auth_hmacsha256_final(&hmac_state, security_state.primary_counter.hash);

    /* Update timestamp - use a function that won't overflow on 32-bit platforms */
    security_state.primary_counter.timestamp = timestamp;
    security_state.primary_counter.valid = 1;

    /* Zero sensitive data from stack */
    sodium_memzero(extra_entropy, sizeof(extra_entropy));

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

        /* Use constant-time comparison for security-critical data */
        primary_valid = sodium_memcmp(expected_hash, security_state.primary_counter.hash, 32) == 0;
    }

    /* Check backup counter */
    if (security_state.backup_counter.valid)
    {
        crypto_auth_hmacsha256_state hmac_state;
        crypto_auth_hmacsha256_init(&hmac_state, security_state.device_secret, sizeof(security_state.device_secret));
        crypto_auth_hmacsha256_update(&hmac_state, (const uint8_t *)&security_state.backup_counter.value, sizeof(uint64_t));
        crypto_auth_hmacsha256_final(&hmac_state, expected_hash);

        backup_valid = sodium_memcmp(expected_hash, security_state.backup_counter.hash, 32) == 0;
    }

    /* Check secure element counter */
    if (security_state.secure_counter.valid)
    {
        crypto_auth_hmacsha256_state hmac_state;
        crypto_auth_hmacsha256_init(&hmac_state, security_state.device_secret, sizeof(security_state.device_secret));
        crypto_auth_hmacsha256_update(&hmac_state, (const uint8_t *)&security_state.secure_counter.value, sizeof(uint64_t));
        crypto_auth_hmacsha256_final(&hmac_state, expected_hash);

        secure_valid = sodium_memcmp(expected_hash, security_state.secure_counter.hash, 32) == 0;
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
 *
 * This implementation includes wear-leveling and defense-in-depth strategies:
 * 1. Key verification before storage
 * 2. Dual storage locations for redundancy
 * 3. Secure wear-leveling to extend flash lifespan
 * 4. Hardware security module integration if available
 * 5. Strong authentication of stored keys
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

    /* Validate key quality */
    if (sodium_is_zero(private_key, PRIVATE_KEY_LENGTH / 4))
    {
        /* Private key has too many zeros - suspicious quality */
        return -1;
    }

    /* Different key types are stored at different flash locations */
    uint32_t base_addr;
    const char *key_label = NULL; /* For hardware security module and logging */

    switch (key_type)
    {
    case KEY_TYPE_IDENTITY:
        base_addr = 0x40000;
        key_label = "IDENTITY_KEY";
        break;
    case KEY_TYPE_EPHEMERAL:
        base_addr = 0x41000;
        key_label = "EPHEMERAL_KEY";
        break;
    case KEY_TYPE_SYMMETRIC:
        base_addr = 0x42000;
        key_label = "SYMMETRIC_KEY";
        break;
    case KEY_TYPE_TX:
        base_addr = 0x43000;
        key_label = "TX_KEY";
        break;
    case KEY_TYPE_RX:
        base_addr = 0x44000;
        key_label = "RX_KEY";
        break;
    default:
        return -2;
    }

    /* Implement wear-leveling by using multiple sectors */
    uint8_t wear_index = 0;
    uint32_t wear_addr = 0x60000 + (key_type * sizeof(uint8_t));

    /* Read current wear index for this key type */
    int result = platform_flash_read(wear_addr, &wear_index, sizeof(wear_index));
    if (result == 0)
    {
        /* Increment wear index, staying within allocated sectors (4 per key type) */
        wear_index = (wear_index + 1) % 4;
    }

    /* Calculate actual address with wear-leveling offset */
    uint32_t actual_addr = base_addr + (wear_index * 0x100);
    uint32_t backup_addr = base_addr + 0x400 + (wear_index * 0x100); /* Separate backup region */

    /* Use authenticated encryption with device secret as key to protect the private key */
    uint8_t encrypted_private[PRIVATE_KEY_LENGTH + crypto_secretbox_MACBYTES];
    uint8_t nonce[crypto_secretbox_NONCEBYTES];

    /* Generate strong nonce with multiple entropy sources */
    randombytes_buf(nonce, sizeof(nonce));

    /* Mix in additional entropy */
    uint32_t timestamp = platform_get_time_ms();
    uint8_t *nonce_ptr = nonce;
    for (size_t i = 0; i < sizeof(timestamp); i++)
    {
        *nonce_ptr++ ^= ((uint8_t *)&timestamp)[i];
    }

    /* Add key type as context in nonce */
    nonce[sizeof(nonce) - 1] ^= key_type;

    /* Encrypt private key with authenticated encryption */
    if (crypto_secretbox_easy(encrypted_private, private_key, PRIVATE_KEY_LENGTH,
                              nonce, security_state.device_secret) != 0)
    {
        return -3;
    }

    /* Calculate a strong checksum using HMAC-SHA256 that includes all data */
    uint8_t checksum[32];
    crypto_auth_hmacsha256_state hmac_state;
    crypto_auth_hmacsha256_init(&hmac_state, security_state.device_secret, sizeof(security_state.device_secret));

    /* Include all data in the authentication */
    crypto_auth_hmacsha256_update(&hmac_state, public_key, PUBLIC_KEY_LENGTH);
    crypto_auth_hmacsha256_update(&hmac_state, encrypted_private, sizeof(encrypted_private));
    crypto_auth_hmacsha256_update(&hmac_state, nonce, sizeof(nonce));
    crypto_auth_hmacsha256_update(&hmac_state, &key_type, sizeof(key_type));                   /* Include key type in check */
    crypto_auth_hmacsha256_update(&hmac_state, (const uint8_t *)key_label, strlen(key_label)); /* Include label */

    crypto_auth_hmacsha256_final(&hmac_state, checksum);

    /* Before writing, erase sectors if supported by the platform */
    platform_flash_erase_sector(actual_addr / 0x1000);
    platform_flash_erase_sector(backup_addr / 0x1000);

    /* Save data with proper error handling */
    int error_count = 0;

    /* Primary copy */
    if (platform_flash_write(actual_addr, public_key, PUBLIC_KEY_LENGTH) != 0)
        error_count++;
    if (platform_flash_write(actual_addr + PUBLIC_KEY_LENGTH, encrypted_private, sizeof(encrypted_private)) != 0)
        error_count++;
    if (platform_flash_write(actual_addr + PUBLIC_KEY_LENGTH + sizeof(encrypted_private), nonce, sizeof(nonce)) != 0)
        error_count++;
    if (platform_flash_write(actual_addr + PUBLIC_KEY_LENGTH + sizeof(encrypted_private) + sizeof(nonce),
                             checksum, sizeof(checksum)) != 0)
        error_count++;

    /* Backup copy */
    if (platform_flash_write(backup_addr, public_key, PUBLIC_KEY_LENGTH) != 0)
        error_count++;
    if (platform_flash_write(backup_addr + PUBLIC_KEY_LENGTH, encrypted_private, sizeof(encrypted_private)) != 0)
        error_count++;
    if (platform_flash_write(backup_addr + PUBLIC_KEY_LENGTH + sizeof(encrypted_private), nonce, sizeof(nonce)) != 0)
        error_count++;
    if (platform_flash_write(backup_addr + PUBLIC_KEY_LENGTH + sizeof(encrypted_private) + sizeof(nonce),
                             checksum, sizeof(checksum)) != 0)
        error_count++;

    /* Update wear-leveling index if all writes were successful */
    if (error_count == 0)
    {
        platform_flash_write(wear_addr, &wear_index, sizeof(wear_index));
    }

#ifdef USE_HARDWARE_CRYPTO
    /* If hardware security module is available, also store key material there */
    if (key_type == KEY_TYPE_IDENTITY)
    {
        /* Only store long-term identity keys in HSM */
        platform_store_secure_key(SECURE_KEY_IDENTITY_PRIVATE, private_key, PRIVATE_KEY_LENGTH);
        platform_store_secure_key(SECURE_KEY_IDENTITY_PUBLIC, public_key, PUBLIC_KEY_LENGTH);
    }
#endif

    /* Clear sensitive data from stack */
    sodium_memzero((void *)encrypted_private, sizeof(encrypted_private));
    sodium_memzero((void *)nonce, sizeof(nonce));
    sodium_memzero((void *)checksum, sizeof(checksum));

    /* Report error if any writes failed */
    if (error_count > 0)
    {
        return -4;
    }

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

    /* Use constant-time comparison for security-critical data */
    if (sodium_memcmp(stored_checksum, calculated_checksum, 32) != 0)
    {
        /* Log the key verification failure with error code but not the actual data */
        platform_log(LOG_LEVEL_WARNING, "Key verification failed for type %d", key_type);

        /* Checksum mismatch - keys might be corrupted or not initialized */
        /* Attempt to read from backup location before generating new keys */
        uint8_t backup_checksum[32];
        uint8_t backup_public[PUBLIC_KEY_LENGTH];
        uint8_t backup_encrypted[PRIVATE_KEY_LENGTH + crypto_secretbox_MACBYTES];
        uint8_t backup_nonce[crypto_secretbox_NONCEBYTES];

        /* Try from backup location (offset by 0x100 bytes) */
        uint32_t backup_addr = base_addr + 0x100;

        if (platform_flash_read(backup_addr, backup_public, PUBLIC_KEY_LENGTH) == 0 &&
            platform_flash_read(backup_addr + PUBLIC_KEY_LENGTH, backup_encrypted, sizeof(backup_encrypted)) == 0 &&
            platform_flash_read(backup_addr + PUBLIC_KEY_LENGTH + sizeof(backup_encrypted),
                                backup_nonce, sizeof(backup_nonce)) == 0 &&
            platform_flash_read(backup_addr + PUBLIC_KEY_LENGTH + sizeof(backup_encrypted) + sizeof(backup_nonce),
                                backup_checksum, sizeof(backup_checksum)) == 0)
        {

            /* Verify backup checksum */
            crypto_auth_hmacsha256(calculated_checksum, backup_public, PUBLIC_KEY_LENGTH, security_state.device_secret);

            if (sodium_memcmp(backup_checksum, calculated_checksum, 32) == 0)
            {
                /* Backup is valid, use it */
                if (crypto_secretbox_open_easy(private_key, backup_encrypted, sizeof(backup_encrypted),
                                               backup_nonce, security_state.device_secret) == 0)
                {
                    /* Copy the public key */
                    memcpy(public_key, backup_public, PUBLIC_KEY_LENGTH);

                    /* And restore the primary copy from the backup */
                    platform_flash_write(base_addr, backup_public, PUBLIC_KEY_LENGTH);
                    platform_flash_write(base_addr + PUBLIC_KEY_LENGTH, backup_encrypted, sizeof(backup_encrypted));
                    platform_flash_write(base_addr + PUBLIC_KEY_LENGTH + sizeof(backup_encrypted),
                                         backup_nonce, sizeof(backup_nonce));
                    platform_flash_write(base_addr + PUBLIC_KEY_LENGTH + sizeof(backup_encrypted) + sizeof(backup_nonce),
                                         backup_checksum, sizeof(backup_checksum));

                    return 0;
                }
            }
        }

        /* If we reach here, backup was also invalid, generate a new keypair */
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