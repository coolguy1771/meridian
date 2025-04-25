#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <stddef.h>

/**
 * @file packet.h
 * @brief Packet structure and handling for the mesh network
 */

/* Packet types */
#define PACKET_TYPE_VOICE         0x01  /* Voice/audio data packet */
#define PACKET_TYPE_HANDSHAKE     0x02  /* Key exchange handshake */
#define PACKET_TYPE_ACK           0x03  /* Acknowledgment */
#define PACKET_TYPE_BEACON        0x04  /* Node beacon/discovery */
#define PACKET_TYPE_CONTROL       0x05  /* Network control message */
#define PACKET_TYPE_TEXT          0x06  /* Text message */
#define PACKET_TYPE_POSITION      0x07  /* Position data */

/* Maximum values */
#define MAX_PACKET_SIZE           255   /* Maximum size of a complete packet */
#define MAX_PAYLOAD_SIZE          200   /* Maximum size of packet payload */
#define MAX_HEADER_SIZE           12    /* Maximum size of the unencrypted header */
#define MAX_NODES                 65535 /* Maximum number of nodes (16-bit address) */
#define MAX_TTL                   10    /* Maximum time-to-live value */
#define BROADCAST_ADDR            0xFFFF /* Broadcast address */

/* Header structure (12 bytes) */
typedef struct __attribute__((packed)) {
    uint16_t destination;    /* Destination node ID (or BROADCAST_ADDR) */
    uint16_t source;         /* Source node ID */
    uint8_t  type;           /* Packet type (see PACKET_TYPE_*) */
    uint8_t  ttl;            /* Time to live / hop count */
    uint16_t sequence;       /* Packet sequence number */
    uint8_t  band_info;      /* Current frequency band and parameters */
    uint8_t  multi_band_flags; /* Capability indicators and routing information */
    uint16_t nonce_fragment; /* Lower bits of counter for integrity checking */
} packet_header_t;

/* Complete packet structure */
typedef struct {
    packet_header_t header;                /* Unencrypted header */
    uint8_t payload[MAX_PAYLOAD_SIZE];     /* Encrypted payload */
    size_t payload_len;                    /* Length of payload in bytes */
    uint8_t tag[16];                       /* Authentication tag */
} packet_t;

/* Recent packet cache entry */
typedef struct {
    uint16_t source;         /* Source node ID */
    uint16_t sequence;       /* Packet sequence number */
    uint8_t  from_node;      /* Node ID we heard this from */
    uint32_t timestamp;      /* When we received this packet */
} recent_packet_t;

/**
 * Initialize the packet handling system
 * 
 * @param our_node_id The node ID for this device
 * @return 0 on success, negative on error
 */
int packet_init(uint16_t our_node_id);

/**
 * Create a new packet with the given parameters
 * 
 * @param packet Pointer to packet structure to fill
 * @param dest_id Destination node ID
 * @param type Packet type
 * @param payload Payload data
 * @param payload_len Length of payload in bytes
 * @return 0 on success, negative on error
 */
int packet_create(
    packet_t* packet,
    uint16_t dest_id,
    uint8_t type,
    const uint8_t* payload,
    size_t payload_len);

/**
 * Encrypt a packet's payload
 * 
 * @param packet Packet to encrypt
 * @param key Encryption key
 * @return 0 on success, negative on error
 */
int packet_encrypt(packet_t* packet, const uint8_t* key);

/**
 * Decrypt a packet's payload
 * 
 * @param packet Packet to decrypt
 * @param key Decryption key
 * @return 0 on success, negative on error
 */
int packet_decrypt(packet_t* packet, const uint8_t* key);

/**
 * Serialize a packet to a byte buffer for transmission
 * 
 * @param packet Packet to serialize
 * @param buffer Buffer to serialize into
 * @param buffer_size Size of buffer in bytes
 * @return Length of serialized packet on success, negative on error
 */
int packet_serialize(
    const packet_t* packet,
    uint8_t* buffer,
    size_t buffer_size);

/**
 * Deserialize a byte buffer into a packet structure
 * 
 * @param buffer Buffer containing serialized packet
 * @param buffer_len Length of buffer in bytes
 * @param packet Pointer to packet structure to fill
 * @return 0 on success, negative on error
 */
int packet_deserialize(
    const uint8_t* buffer,
    size_t buffer_len,
    packet_t* packet);

/**
 * Handle a received packet (forwarding logic)
 * 
 * @param packet Received packet
 * @param from_node Node ID we received this from (0 if direct)
 * @return 0 if packet was for us, 1 if forwarded, negative on error
 */
int packet_handle(const packet_t* packet, uint16_t from_node);

/**
 * Check if we've seen this packet before
 * 
 * @param source Source node ID
 * @param sequence Packet sequence number
 * @return 1 if seen before, 0 if not
 */
int packet_seen_before(uint16_t source, uint16_t sequence);

/**
 * Add a packet to the seen cache
 * 
 * @param source Source node ID
 * @param sequence Packet sequence number
 * @param from_node Node ID we received this from
 * @return 0 on success, negative on error
 */
int packet_add_to_cache(uint16_t source, uint16_t sequence, uint16_t from_node);

#endif /* PACKET_H */