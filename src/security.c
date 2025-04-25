#include "security.h"
#include "platform.h"
#include <string.h>
#include <stdlib.h>

/* Flash storage addresses for monotonic counters */
#define COUNTER_PRIMARY_ADDR   0x10000
#define COUNTER_BACKUP_ADDR    0x20000
#define COUNTER_SECURE_ADDR    0x30000

/* Module state */
static struct {
    uint8_t mode;
    uint8_t cipher;
    uint8_t node_id[NODE_ID_LENGTH];
    monotonic_counter_t primary_counter;
    monotonic_counter_t backup_counter;
    monotonic_counter_t secure_counter;
    uint8_t device_secret[32]; /* Secret key for counter integrity */
} security_state;

/* Simple SHA-256 mock function for simulation */
static void mock_sha256(const void* data, size_t len, uint8_t hash[32]) {
    /* In a real implementation, this would use a proper SHA-256 implementation */
    /* For simulation, we'll just create a simple hash function */
    
    memset(hash, 0, 32);
    const uint8_t* bytes = (const uint8_t*)data;
    
    for (size_t i = 0; i < len; i++) {
        hash[i % 32] ^= bytes[i];
        hash[(i + 7) % 32] += bytes[i];
        
        /* Simple mixing */
        for (int j = 0; j < 32; j++) {
            hash[(j + 1) % 32] ^= (hash[j] << 1) | (hash[j] >> 7);
        }
    }
}

/* Mock AES-GCM encryption for simulation */
static int mock_aes_gcm_encrypt(
    const uint8_t* key,
    const uint8_t* iv,
    size_t iv_len,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    uint8_t* tag,
    size_t tag_len)
{
    /* In a real implementation, this would use a proper AES-GCM implementation */
    /* For simulation, we'll just XOR the data with the key and generate a tag */
    
    /* "Encrypt" by XORing with key bytes (completely insecure, just for simulation) */
    for (size_t i = 0; i < plaintext_len; i++) {
        ciphertext[i] = plaintext[i] ^ key[i % SYMMETRIC_KEY_LENGTH];
    }
    
    /* Generate a tag by hashing key, IV, AAD, and ciphertext */
    uint8_t* hash_data = malloc(SYMMETRIC_KEY_LENGTH + iv_len + aad_len + plaintext_len);
    if (!hash_data) {
        return -1;
    }
    
    size_t offset = 0;
    memcpy(hash_data + offset, key, SYMMETRIC_KEY_LENGTH);
    offset += SYMMETRIC_KEY_LENGTH;
    
    memcpy(hash_data + offset, iv, iv_len);
    offset += iv_len;
    
    if (aad && aad_len > 0) {
        memcpy(hash_data + offset, aad, aad_len);
        offset += aad_len;
    }
    
    memcpy(hash_data + offset, ciphertext, plaintext_len);
    offset += plaintext_len;
    
    uint8_t hash[32];
    mock_sha256(hash_data, offset, hash);
    free(hash_data);
    
    /* Copy the first tag_len bytes of the hash as the tag */
    memcpy(tag, hash, tag_len);
    
    return 0;
}

/* Mock AES-GCM decryption for simulation */
static int mock_aes_gcm_decrypt(
    const uint8_t* key,
    const uint8_t* iv,
    size_t iv_len,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* tag,
    size_t tag_len,
    uint8_t* plaintext)
{
    /* Generate expected tag */
    uint8_t expected_tag[TAG_LENGTH];
    
    uint8_t* hash_data = malloc(SYMMETRIC_KEY_LENGTH + iv_len + aad_len + ciphertext_len);
    if (!hash_data) {
        return -1;
    }
    
    size_t offset = 0;
    memcpy(hash_data + offset, key, SYMMETRIC_KEY_LENGTH);
    offset += SYMMETRIC_KEY_LENGTH;
    
    memcpy(hash_data + offset, iv, iv_len);
    offset += iv_len;
    
    if (aad && aad_len > 0) {
        memcpy(hash_data + offset, aad, aad_len);
        offset += aad_len;
    }
    
    memcpy(hash_data + offset, ciphertext, ciphertext_len);
    offset += ciphertext_len;
    
    uint8_t hash[32];
    mock_sha256(hash_data, offset, hash);
    free(hash_data);
    
    /* Copy the first tag_len bytes of the hash as the expected tag */
    memcpy(expected_tag, hash, tag_len);
    
    /* Verify tag */
    if (memcmp(expected_tag, tag, tag_len) != 0) {
        return -2; /* Authentication failed */
    }
    
    /* "Decrypt" by XORing with key bytes (completely insecure, just for simulation) */
    for (size_t i = 0; i < ciphertext_len; i++) {
        plaintext[i] = ciphertext[i] ^ key[i % SYMMETRIC_KEY_LENGTH];
    }
    
    return 0;
}

/* Mock ChaCha20-Poly1305 encryption for simulation (identical to AES-GCM for simulation) */
static int mock_chacha20_poly1305_encrypt(
    const uint8_t* key,
    const uint8_t* iv,
    size_t iv_len,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    uint8_t* tag,
    size_t tag_len)
{
    return mock_aes_gcm_encrypt(key, iv, iv_len, aad, aad_len, plaintext, plaintext_len, ciphertext, tag, tag_len);
}

/* Mock ChaCha20-Poly1305 decryption for simulation (identical to AES-GCM for simulation) */
static int mock_chacha20_poly1305_decrypt(
    const uint8_t* key,
    const uint8_t* iv,
    size_t iv_len,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* tag,
    size_t tag_len,
    uint8_t* plaintext)
{
    return mock_aes_gcm_decrypt(key, iv, iv_len, aad, aad_len, ciphertext, ciphertext_len, tag, tag_len, plaintext);
}

/* Mock ECDH key agreement for simulation */
static int mock_ecdh_compute_shared(
    const uint8_t* public_key,
    const uint8_t* private_key,
    uint8_t* shared_secret)
{
    /* In a real implementation, this would perform actual ECDH computation */
    /* For simulation, we'll just hash the public and private keys together */
    
    uint8_t combined[PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH];
    memcpy(combined, public_key, PUBLIC_KEY_LENGTH);
    memcpy(combined + PUBLIC_KEY_LENGTH, private_key, PRIVATE_KEY_LENGTH);
    
    mock_sha256(combined, sizeof(combined), shared_secret);
    
    return 0;
}

/**
 * Initialize the security subsystem
 */
int security_init(uint8_t mode, uint8_t cipher) {
    /* Validate parameters */
    if (mode > SECURITY_E2E_AUTH || cipher > CIPHER_CHACHA20_POLY) {
        return -1;
    }
    
    /* Initialize state */
    security_state.mode = mode;
    security_state.cipher = cipher;
    
    /* Generate a device secret for counter integrity */
    platform_random_bytes(security_state.device_secret, sizeof(security_state.device_secret));
    
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
int security_generate_keypair(uint8_t key_type, uint8_t* public_key, uint8_t* private_key) {
    if (!public_key || !private_key) {
        return -1;
    }
    
    /* Generate random private key */
    platform_random_bytes(private_key, PRIVATE_KEY_LENGTH);
    
    /* In a real implementation, this would derive a public key using ECC */
    /* For simulation, we'll just use a hash of the private key */
    mock_sha256(private_key, PRIVATE_KEY_LENGTH, public_key);
    
    /* For simulation, fill the rest of the public key with more random data */
    platform_random_bytes(public_key + 32, PUBLIC_KEY_LENGTH - 32);
    
    return 0;
}

/**
 * Perform ECDH key exchange to derive a shared secret
 */
int security_compute_shared_secret(
    const uint8_t* peer_public_key,
    const uint8_t* our_private_key,
    uint8_t* shared_secret)
{
    if (!peer_public_key || !our_private_key || !shared_secret) {
        return -1;
    }
    
    return mock_ecdh_compute_shared(peer_public_key, our_private_key, shared_secret);
}

/**
 * Derive symmetric keys from a shared secret
 */
int security_derive_keys(
    const uint8_t* shared_secret,
    uint8_t* tx_key,
    uint8_t* rx_key)
{
    if (!shared_secret || !tx_key || !rx_key) {
        return -1;
    }
    
    /* For TX key, hash the shared secret with a "tx" prefix */
    uint8_t tx_data[SHARED_SECRET_LENGTH + 2];
    memcpy(tx_data, shared_secret, SHARED_SECRET_LENGTH);
    tx_data[SHARED_SECRET_LENGTH] = 't';
    tx_data[SHARED_SECRET_LENGTH + 1] = 'x';
    mock_sha256(tx_data, sizeof(tx_data), tx_key);
    
    /* For RX key, hash the shared secret with an "rx" prefix */
    uint8_t rx_data[SHARED_SECRET_LENGTH + 2];
    memcpy(rx_data, shared_secret, SHARED_SECRET_LENGTH);
    rx_data[SHARED_SECRET_LENGTH] = 'r';
    rx_data[SHARED_SECRET_LENGTH + 1] = 'x';
    mock_sha256(rx_data, sizeof(rx_data), rx_key);
    
    return 0;
}

/**
 * Encrypt a packet using the configured cipher
 */
int security_encrypt(
    const uint8_t* key,
    const secure_nonce_t* nonce,
    const uint8_t* plaintext,
    size_t plaintext_len,
    const uint8_t* associated_data,
    size_t associated_data_len,
    uint8_t* ciphertext,
    uint8_t* tag)
{
    if (!key || !nonce || !plaintext || !ciphertext || !tag) {
        return -1;
    }
    
    /* Prepare nonce as a byte array */
    uint8_t nonce_bytes[NONCE_LENGTH];
    memcpy(nonce_bytes, nonce->node_id, sizeof(nonce->node_id));
    memcpy(nonce_bytes + sizeof(nonce->node_id), &nonce->counter, sizeof(nonce->counter));
    nonce_bytes[NONCE_LENGTH - 1] = nonce->random;
    
    /* Use the appropriate cipher */
    if (security_state.cipher == CIPHER_AES_GCM) {
        return mock_aes_gcm_encrypt(
            key, nonce_bytes, NONCE_LENGTH,
            associated_data, associated_data_len,
            plaintext, plaintext_len,
            ciphertext, tag, TAG_LENGTH);
    } else { /* CIPHER_CHACHA20_POLY */
        return mock_chacha20_poly1305_encrypt(
            key, nonce_bytes, NONCE_LENGTH,
            associated_data, associated_data_len,
            plaintext, plaintext_len,
            ciphertext, tag, TAG_LENGTH);
    }
}

/**
 * Decrypt a packet using the configured cipher
 */
int security_decrypt(
    const uint8_t* key,
    const secure_nonce_t* nonce,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* associated_data,
    size_t associated_data_len,
    const uint8_t* tag,
    uint8_t* plaintext)
{
    if (!key || !nonce || !ciphertext || !plaintext || !tag) {
        return -1;
    }
    
    /* Prepare nonce as a byte array */
    uint8_t nonce_bytes[NONCE_LENGTH];
    memcpy(nonce_bytes, nonce->node_id, sizeof(nonce->node_id));
    memcpy(nonce_bytes + sizeof(nonce->node_id), &nonce->counter, sizeof(nonce->counter));
    nonce_bytes[NONCE_LENGTH - 1] = nonce->random;
    
    /* Use the appropriate cipher */
    if (security_state.cipher == CIPHER_AES_GCM) {
        return mock_aes_gcm_decrypt(
            key, nonce_bytes, NONCE_LENGTH,
            associated_data, associated_data_len,
            ciphertext, ciphertext_len,
            tag, TAG_LENGTH,
            plaintext);
    } else { /* CIPHER_CHACHA20_POLY */
        return mock_chacha20_poly1305_decrypt(
            key, nonce_bytes, NONCE_LENGTH,
            associated_data, associated_data_len,
            ciphertext, ciphertext_len,
            tag, TAG_LENGTH,
            plaintext);
    }
}

/**
 * Get the next nonce for a transmission
 */
int security_get_next_nonce(secure_nonce_t* nonce) {
    if (!nonce) {
        return -1;
    }
    
    /* Use device ID for node_id */
    memcpy(nonce->node_id, security_state.node_id, NODE_ID_LENGTH);
    
    /* Set counter from primary counter */
    nonce->counter = security_state.primary_counter.value++;
    
    /* Generate random byte */
    platform_random_bytes(&nonce->random, 1);
    
    /* Update counter hash */
    uint8_t data[sizeof(uint64_t) + sizeof(security_state.device_secret)];
    memcpy(data, &security_state.primary_counter.value, sizeof(uint64_t));
    memcpy(data + sizeof(uint64_t), security_state.device_secret, sizeof(security_state.device_secret));
    mock_sha256(data, sizeof(data), security_state.primary_counter.hash);
    
    /* Update timestamp */
    security_state.primary_counter.timestamp = platform_get_time_ms();
    security_state.primary_counter.valid = 1;
    
    /* Periodically save to flash (in a real implementation) */
    /* For simulation, we'll save every time */
    platform_flash_write(COUNTER_PRIMARY_ADDR, &security_state.primary_counter, sizeof(monotonic_counter_t));
    
    /* Update backup if it's significantly behind */
    if (security_state.primary_counter.value - security_state.backup_counter.value > 1000) {
        security_state.backup_counter = security_state.primary_counter;
        platform_flash_write(COUNTER_BACKUP_ADDR, &security_state.backup_counter, sizeof(monotonic_counter_t));
    }
    
    /* Update secure element counter (high bits only) */
    uint32_t high_bits = (uint32_t)(security_state.primary_counter.value >> 32);
    if (high_bits > (uint32_t)(security_state.secure_counter.value >> 32)) {
        security_state.secure_counter.value = security_state.primary_counter.value;
        security_state.secure_counter.timestamp = security_state.primary_counter.timestamp;
        security_state.secure_counter.valid = 1;
        
        /* Update hash */
        uint8_t sec_data[sizeof(uint64_t) + sizeof(security_state.device_secret)];
        memcpy(sec_data, &security_state.secure_counter.value, sizeof(uint64_t));
        memcpy(sec_data + sizeof(uint64_t), security_state.device_secret, sizeof(security_state.device_secret));
        mock_sha256(sec_data, sizeof(sec_data), security_state.secure_counter.hash);
        
        platform_flash_write(COUNTER_SECURE_ADDR, &security_state.secure_counter, sizeof(monotonic_counter_t));
    }
    
    return 0;
}

/**
 * Verify the integrity of the monotonic counter system
 */
int security_verify_counter_integrity(void) {
    /* Verify hash of primary counter */
    uint8_t expected_hash[32];
    uint8_t data[sizeof(uint64_t) + sizeof(security_state.device_secret)];
    int primary_valid = 0, backup_valid = 0, secure_valid = 0;
    
    /* Check primary counter */
    if (security_state.primary_counter.valid) {
        memcpy(data, &security_state.primary_counter.value, sizeof(uint64_t));
        memcpy(data + sizeof(uint64_t), security_state.device_secret, sizeof(security_state.device_secret));
        mock_sha256(data, sizeof(data), expected_hash);
        
        primary_valid = memcmp(expected_hash, security_state.primary_counter.hash, 32) == 0;
    }
    
    /* Check backup counter */
    if (security_state.backup_counter.valid) {
        memcpy(data, &security_state.backup_counter.value, sizeof(uint64_t));
        memcpy(data + sizeof(uint64_t), security_state.device_secret, sizeof(security_state.device_secret));
        mock_sha256(data, sizeof(data), expected_hash);
        
        backup_valid = memcmp(expected_hash, security_state.backup_counter.hash, 32) == 0;
    }
    
    /* Check secure element counter */
    if (security_state.secure_counter.valid) {
        memcpy(data, &security_state.secure_counter.value, sizeof(uint64_t));
        memcpy(data + sizeof(uint64_t), security_state.device_secret, sizeof(security_state.device_secret));
        mock_sha256(data, sizeof(data), expected_hash);
        
        secure_valid = memcmp(expected_hash, security_state.secure_counter.hash, 32) == 0;
    }
    
    /* Determine the correct counter through voting and validation */
    if (primary_valid && backup_valid && security_state.primary_counter.value == security_state.backup_counter.value) {
        /* Both primary and backup are valid and match */
        return 0;
    } else if (primary_valid && secure_valid && 
              (security_state.primary_counter.value >> 32) == (security_state.secure_counter.value >> 32)) {
        /* Primary and secure element high bits match */
        return 0;
    } else if (backup_valid && secure_valid && 
              (security_state.backup_counter.value >> 32) == (security_state.secure_counter.value >> 32)) {
        /* Backup and secure element high bits match */
        security_state.primary_counter = security_state.backup_counter;
        platform_flash_write(COUNTER_PRIMARY_ADDR, &security_state.primary_counter, sizeof(monotonic_counter_t));
        return 0;
    } else if (primary_valid && backup_valid && secure_valid) {
        /* All valid but different - use highest value */
        uint64_t max_value = security_state.primary_counter.value;
        if (security_state.backup_counter.value > max_value) {
            max_value = security_state.backup_counter.value;
        }
        if (security_state.secure_counter.value > max_value) {
            max_value = security_state.secure_counter.value;
        }
        
        security_state.primary_counter.value = max_value;
        security_state.primary_counter.timestamp = platform_get_time_ms();
        
        /* Update hash */
        memcpy(data, &security_state.primary_counter.value, sizeof(uint64_t));
        memcpy(data + sizeof(uint64_t), security_state.device_secret, sizeof(security_state.device_secret));
        mock_sha256(data, sizeof(data), security_state.primary_counter.hash);
        
        platform_flash_write(COUNTER_PRIMARY_ADDR, &security_state.primary_counter, sizeof(monotonic_counter_t));
        
        /* Update backup too */
        security_state.backup_counter = security_state.primary_counter;
        platform_flash_write(COUNTER_BACKUP_ADDR, &security_state.backup_counter, sizeof(monotonic_counter_t));
        
        return 0;
    } else if (primary_valid) {
        /* Only primary is valid */
        return 0;
    } else if (backup_valid) {
        /* Only backup is valid */
        security_state.primary_counter = security_state.backup_counter;
        platform_flash_write(COUNTER_PRIMARY_ADDR, &security_state.primary_counter, sizeof(monotonic_counter_t));
        return 0;
    } else if (secure_valid) {
        /* Only secure element is valid - reconstruct from high bits */
        security_state.primary_counter.value = security_state.secure_counter.value;
        security_state.primary_counter.timestamp = platform_get_time_ms();
        security_state.primary_counter.valid = 1;
        
        /* Update hash */
        memcpy(data, &security_state.primary_counter.value, sizeof(uint64_t));
        memcpy(data + sizeof(uint64_t), security_state.device_secret, sizeof(security_state.device_secret));
        mock_sha256(data, sizeof(data), security_state.primary_counter.hash);
        
        platform_flash_write(COUNTER_PRIMARY_ADDR, &security_state.primary_counter, sizeof(monotonic_counter_t));
        
        return 0;
    } else {
        /* All verification failed - potential tampering */
        /* For now, initialize with a new counter */
        security_state.primary_counter.value = 1000000; /* Start with a large safety margin */
        security_state.primary_counter.timestamp = platform_get_time_ms();
        security_state.primary_counter.valid = 1;
        
        /* Update hash */
        memcpy(data, &security_state.primary_counter.value, sizeof(uint64_t));
        memcpy(data + sizeof(uint64_t), security_state.device_secret, sizeof(security_state.device_secret));
        mock_sha256(data, sizeof(data), security_state.primary_counter.hash);
        
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
    const uint8_t* public_key,
    const uint8_t* private_key)
{
    if (!public_key || !private_key) {
        return -1;
    }
    
    /* In a real implementation, this would store keys in flash or secure element */
    /* For simulation, we'll just pretend it worked */
    return 0;
}

/**
 * Load public and private keys from persistent storage
 */
int security_load_keys(
    uint8_t key_type,
    uint8_t* public_key,
    uint8_t* private_key)
{
    if (!public_key || !private_key) {
        return -1;
    }
    
    /* In a real implementation, this would load keys from flash or secure element */
    /* For simulation, we'll generate a new keypair */
    return security_generate_keypair(key_type, public_key, private_key);
}