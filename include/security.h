#ifndef SECURITY_H
#define SECURITY_H

#include <stdint.h>
#include <stddef.h>

/**
 * @file security.h
 * @brief Cryptographic functionality for secure communications
 * 
 * This module implements secure cryptographic operations for the radio
 * mesh network. It relies on libsodium for strong, audited cryptographic
 * primitives.
 */

/* libsodium is required */
#include <sodium.h>

/* Encryption types */
#define CIPHER_AES_GCM         0    /* AES-256 in GCM mode (hardware accelerated) */
#define CIPHER_CHACHA20_POLY   1    /* ChaCha20-Poly1305 (software) */

/* Security modes */
#define SECURITY_NONE          0    /* No encryption (for testing only) */
#define SECURITY_E2E           1    /* End-to-end encryption only */
#define SECURITY_E2E_AUTH      2    /* End-to-end with authentication */

/* Key types */
#define KEY_TYPE_IDENTITY      0    /* Long-term identity key */
#define KEY_TYPE_EPHEMERAL     1    /* Ephemeral session key */
#define KEY_TYPE_SYMMETRIC     2    /* Derived symmetric key */
#define KEY_TYPE_TX            3    /* Transmission key */
#define KEY_TYPE_RX            4    /* Reception key */

/* Constants */
#define PUBLIC_KEY_LENGTH      64   /* X25519 or secp256r1 public key length in bytes */
#define PRIVATE_KEY_LENGTH     32   /* Private key length in bytes */
#define SHARED_SECRET_LENGTH   32   /* ECDH shared secret length in bytes */
#define SYMMETRIC_KEY_LENGTH   32   /* AES-256 or ChaCha20 key length in bytes */
#define NONCE_LENGTH           12   /* GCM/ChaCha20 nonce length in bytes */
#define TAG_LENGTH             16   /* Authentication tag length in bytes */
#define NODE_ID_LENGTH         4    /* Node identifier length in bytes */
#define RANDOM_BYTES_LENGTH    1    /* Random component of nonce */

/* Nonce structure (13 bytes) */
typedef struct {
    uint8_t node_id[4];             /* First 4 bytes of device unique identifier */
    uint64_t counter;               /* 64-bit monotonic counter */
    uint8_t random;                 /* Single random byte for additional entropy */
} secure_nonce_t;

/* Monotonic counter storage */
typedef struct {
    uint64_t value;                 /* Current counter value */
    uint8_t hash[32];               /* SHA-256 hash of counter + device secret */
    uint32_t timestamp;             /* Timestamp of last update */
    uint8_t valid;                  /* 1 if this counter is valid, 0 otherwise */
} monotonic_counter_t;

/**
 * Initialize the security subsystem
 * 
 * @param mode Security mode to use
 * @param cipher Cipher type to use
 * @return 0 on success, negative on error
 */
int security_init(uint8_t mode, uint8_t cipher);

/**
 * Generate a new key pair for this device
 * 
 * @param key_type Type of key to generate
 * @param public_key Buffer to store public key (PUBLIC_KEY_LENGTH bytes)
 * @param private_key Buffer to store private key (PRIVATE_KEY_LENGTH bytes)
 * @return 0 on success, negative on error
 */
int security_generate_keypair(uint8_t key_type, uint8_t* public_key, uint8_t* private_key);

/**
 * Perform ECDH key exchange to derive a shared secret
 * 
 * @param peer_public_key Public key of the peer (PUBLIC_KEY_LENGTH bytes)
 * @param our_private_key Our private key (PRIVATE_KEY_LENGTH bytes)
 * @param shared_secret Buffer to store shared secret (SHARED_SECRET_LENGTH bytes)
 * @return 0 on success, negative on error
 */
int security_compute_shared_secret(
    const uint8_t* peer_public_key,
    const uint8_t* our_private_key,
    uint8_t* shared_secret);

/**
 * Derive symmetric keys from a shared secret
 * 
 * @param shared_secret ECDH shared secret (SHARED_SECRET_LENGTH bytes)
 * @param tx_key Buffer to store transmit key (SYMMETRIC_KEY_LENGTH bytes)
 * @param rx_key Buffer to store receive key (SYMMETRIC_KEY_LENGTH bytes)
 * @return 0 on success, negative on error
 */
int security_derive_keys(
    const uint8_t* shared_secret,
    uint8_t* tx_key,
    uint8_t* rx_key);

/**
 * Encrypt a packet using the configured cipher
 * 
 * @param key Symmetric key for encryption (SYMMETRIC_KEY_LENGTH bytes)
 * @param nonce Nonce structure for this packet
 * @param plaintext Data to encrypt
 * @param plaintext_len Length of plaintext in bytes
 * @param associated_data Additional authenticated data (can be NULL)
 * @param associated_data_len Length of associated data in bytes (0 if NULL)
 * @param ciphertext Buffer to store encrypted data (must be >= plaintext_len)
 * @param tag Buffer to store authentication tag (TAG_LENGTH bytes)
 * @return Length of ciphertext on success, negative on error
 */
int security_encrypt(
    const uint8_t* key,
    const secure_nonce_t* nonce,
    const uint8_t* plaintext,
    size_t plaintext_len,
    const uint8_t* associated_data,
    size_t associated_data_len,
    uint8_t* ciphertext,
    uint8_t* tag);

/**
 * Decrypt a packet using the configured cipher
 * 
 * @param key Symmetric key for decryption (SYMMETRIC_KEY_LENGTH bytes)
 * @param nonce Nonce structure for this packet
 * @param ciphertext Encrypted data
 * @param ciphertext_len Length of ciphertext in bytes
 * @param associated_data Additional authenticated data (can be NULL)
 * @param associated_data_len Length of associated data in bytes (0 if NULL)
 * @param tag Authentication tag (TAG_LENGTH bytes)
 * @param plaintext Buffer to store decrypted data (must be >= ciphertext_len)
 * @return Length of plaintext on success, negative on error
 */
int security_decrypt(
    const uint8_t* key,
    const secure_nonce_t* nonce,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* associated_data,
    size_t associated_data_len,
    const uint8_t* tag,
    uint8_t* plaintext);

/**
 * Get the next nonce for a transmission
 * 
 * @param nonce Pointer to nonce structure to fill
 * @return 0 on success, negative on error
 */
int security_get_next_nonce(secure_nonce_t* nonce);

/**
 * Verify the integrity of the monotonic counter system
 * 
 * @return 0 on success, negative on error
 */
int security_verify_counter_integrity(void);

/**
 * Store public and private keys to persistent storage
 * 
 * @param key_type Type of key to store
 * @param public_key Public key to store (PUBLIC_KEY_LENGTH bytes)
 * @param private_key Private key to store (PRIVATE_KEY_LENGTH bytes)
 * @return 0 on success, negative on error
 */
int security_store_keys(
    uint8_t key_type,
    const uint8_t* public_key,
    const uint8_t* private_key);

/**
 * Load public and private keys from persistent storage
 * 
 * @param key_type Type of key to load
 * @param public_key Buffer to store public key (PUBLIC_KEY_LENGTH bytes)
 * @param private_key Buffer to store private key (PRIVATE_KEY_LENGTH bytes)
 * @return 0 on success, negative on error
 */
int security_load_keys(
    uint8_t key_type,
    uint8_t* public_key,
    uint8_t* private_key);

#endif /* SECURITY_H */