#ifndef SECURITY_H
#define SECURITY_H

#include <stdint.h>
#include <stddef.h>

/**
 * @file security.h
 * @brief Cryptographic functionality for secure mesh communications.
 */

/* libsodium is required - use it for all crypto primitives */
#include <sodium.h>

/* Constants derived from libsodium API sizes */
#define PUBLIC_KEY_LENGTH      crypto_box_PUBLICKEYBYTES                 /* X25519 pub: 32 */
#define PRIVATE_KEY_LENGTH     crypto_box_SECRETKEYBYTES                 /* X25519 sec: 32 */
#define SHARED_SECRET_LENGTH   crypto_scalarmult_BYTES                   /* DH secret: 32 */
#define SYMMETRIC_KEY_LENGTH   crypto_aead_xchacha20poly1305_ietf_KEYBYTES  /* 32 */
#define TAG_LENGTH             crypto_aead_xchacha20poly1305_ietf_ABYTES    /* 16 */
#define NODE_ID_LENGTH         4

/* Cipher: XChaCha20-Poly1305 for robust AEAD + extended nonce space */
#define CIPHER_XCHACHA20_POLY  0

/* Security modes */
#define SECURITY_NONE          0    /* No encryption (testing only) */
#define SECURITY_E2E           1    /* End-to-end encryption */
#define SECURITY_E2E_AUTH      2    /* End-to-end + authenticated headers */

/* Key types for persistent storage */
#define KEY_TYPE_IDENTITY      0    /* Long-term X25519 identity key pair */
#define KEY_TYPE_EPHEMERAL     1    /* Ephemeral handshake key (not persisted long-term) */
#define KEY_TYPE_NETWORK       3    /* Network-level shared PSK for group comms */
#define KEY_TYPE_GROUP         4    /* Group symmetric key (PSK per group ID) */

/* Handshake message types */
#define HANDSHAKE_TYPE_HELLO       0x01
#define HANDSHAKE_TYPE_RESPONSE    0x02
#define HANDSHAKE_TYPE_CONFIRM     0x03

typedef struct __attribute__((packed)) {
    uint8_t type;                    /* HANDSHAKE_TYPE_* */
    uint16_t initiator_id;           /* Node that initiated handshake */
    uint16_t responder_id;           /* Target node (0 if not yet assigned) */
    uint8_t public_key[PUBLIC_KEY_LENGTH];  /* X25519 public key for DH */
} handshake_message_t;

typedef struct {
    uint16_t peer_id;                             /* Peer node ID this session is with */
    uint8_t session_key[SYMMETRIC_KEY_LENGTH];    /* Derived symmetric encryption key */
    uint32_t established_time;                    /* Boot-time when session was established */
    uint8_t active;                               /* 1 = valid session, 0 = expired/invalid */
} session_info_t;

/* Group key info: stores a shared group PSK per group_id */
typedef struct {
    uint16_t group_id;                            /* Group ID this key belongs to */
    uint8_t  group_key[SYMMETRIC_KEY_LENGTH];     /* Shared symmetric key for the group */
    uint32_t epoch;                               /* Key rotation epoch counter */
    uint8_t  leader_id;                           /* Which node is group leader (for revocations) */
    uint8_t  active;                              /* 1 = valid group membership, 0 = removed/expired */
} group_key_info_t;

#define MAX_ACTIVE_SESSIONS 16     /* Max concurrent per-peer sessions supported */
#define MAX_GROUP_KEYS      8      /* Max groups this node can be a member of */

/* Nonce structure: we transmit an 8-byte nonce in the packet header. */
typedef struct {
    uint64_t value;    /* Full 8-byte nonce value transmitted in packet headers */
} secure_nonce_t;

#define NONCE_MONOTONIC_BITS   40
#define NONCE_RANDOM_BITS      24
#define NONCE_RANDOM_MASK      ((1ULL << NONCE_RANDOM_BITS) - 1)

/* Monotonic counter stored in flash for persistence across reboots */
typedef struct {
    uint64_t value;                 /* Current persistent counter value */
    uint8_t hash[32];               /* HMAC-SHA256 of counter + device secret (integrity) */
    uint32_t timestamp;             /* Timestamp of last update (boot ms) */
    uint8_t valid;                  /* 1 if this entry is considered valid */
} monotonic_counter_t;

/* API */

int security_init(uint8_t mode, uint8_t cipher);
int security_get_identity_public_key(uint8_t* out_pubkey);

int security_compute_shared_secret(
    const uint8_t* peer_public_key,
    uint8_t* shared_secret_out);

int security_derive_session_key(
    const uint8_t* shared_secret,
    uint16_t our_id,
    uint16_t peer_id,
    uint8_t* session_key_out);

int security_encrypt(
    const uint8_t* key,
    const secure_nonce_t* nonce,
    const uint8_t* plaintext,
    size_t plaintext_len,
    const uint8_t* aad,
    size_t aad_len,
    uint8_t* ciphertext_out,
    uint8_t* tag_out);

int security_decrypt(
    const uint8_t* key,
    const secure_nonce_t* nonce,
    const uint8_t* ciphertext_in,
    size_t ciphertext_len,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* tag_in,
    uint8_t* plaintext_out);

int security_get_next_nonce(secure_nonce_t* out_nonce);

int security_store_identity_keys(const uint8_t* public_key, const uint8_t* private_key);
int security_load_identity_keys(uint8_t* out_public_key, uint8_t* out_private_key);

/* Session management */
int security_set_session(uint16_t peer_id, const uint8_t* session_key);
int security_get_session_key(uint16_t peer_id, uint8_t* out_key);

/* Handshake protocol handling */
int security_process_handshake(
    const handshake_message_t* msg,
    uint16_t our_node_id,
    handshake_message_t* response_out);

/* Group key management (leader-based provisioning) */

/* Create or set the shared key for a group; callsite is typically the leader.
 * On leader: generates if key is NULL; on member: called after receiving GROUP_JOIN from leader. */
int security_set_group_key(uint16_t group_id, const uint8_t* key_in, uint16_t leader_id);

/* Get the active symmetric key for a specific group (if this node is a member). */
int security_get_group_key(uint16_t group_id, uint8_t* out_key);

/* Generate the shared secret needed to encrypt a GROUP_JOIN message for a specific peer:
 * derives an ephemeral pairwise key from our identity and their public key.
 * Returns 0 on success with 'shared' filled (SHARED_SECRET_LENGTH bytes). */
int security_derive_pairwise_for_peer(
    const uint8_t* peer_public_key,
    uint16_t peer_id,
    uint8_t* shared);

#endif /* SECURITY_H */
