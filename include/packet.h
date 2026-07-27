#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <stddef.h>
#include "security.h"   /* For TAG_LENGTH, NONCE_* macros */

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
#define PACKET_TYPE_GROUP_JOIN    0x10  /* Group join invitation from leader to member */
#define PACKET_TYPE_GROUP_CHAT    0x11  /* Encrypted group chat packet (uses group PSK) */

/* GROUP_JOIN payload structure sent by leader to new member, encrypted under their pairwise session key. */
typedef struct __attribute__((packed)) {
    uint16_t group_id;          /* Group the node is being added to */
    uint32_t epoch;             /* Key rotation epoch counter for future revocations */
    uint8_t  group_key[SYMMETRIC_KEY_LENGTH];  /* Shared symmetric key for group comms */
} group_join_payload_t;

/* Maximum values */
#define MAX_PACKET_SIZE           255   /* Max complete packet size */
#define MAX_PAYLOAD_SIZE          180   /* Payload max (headroom for header+tag) */
#define MAX_NODES                 65535 /* Max nodes (16-bit address) */
#define MAX_TTL                   10    /* Max TTL/hops */
#define BROADCAST_ADDR            0xFFFF

/* Header structure: 18 bytes packed. Includes band_info for routing + full nonce value. */
typedef struct __attribute__((packed)) {
    uint16_t destination;       /* Destination node ID (or BROADCAST_ADDR) */
    uint16_t source;            /* Source node ID */
    uint8_t  type;              /* Packet type (PACKET_TYPE_*) */
    uint8_t  ttl;               /* Time to live / hop count */
    uint32_t sequence;          /* Packet sequence number (32-bit for mesh-scale) */
    uint8_t  band_info;         /* Band/routing: low 2 bits = band index, high bits reserved */
    uint8_t  multi_band_flags;  /* Capability/multi-band routing flags */
    uint64_t nonce_value;       /* Full nonce transmitted by sender for decryption */
} packet_header_t;

/* Complete packet structure */
typedef struct {
    packet_header_t header;                /* Unencrypted header */
    uint8_t payload[MAX_PAYLOAD_SIZE];     /* Encrypted payload */
    size_t payload_len;                    /* Length of payload in bytes */
    uint8_t tag[TAG_LENGTH];               /* Authentication tag */
} packet_t;

/* Recent packet cache entry - tracks (source, sequence) to prevent replays */
typedef struct {
    uint16_t source;         /* Source node ID */
    uint32_t sequence;       /* Packet sequence number */
    uint8_t  from_node;      /* Node ID we heard this from */
    uint32_t timestamp;      /* When we received this packet */
} recent_packet_t;

/* Replay window size per source node for sliding-window replay protection.
 * Must fit in a 64-bit bitmask, so max practical value is 64. */
#define REPLAY_WINDOW_SIZE 64

/* Per-source replay tracking structure */
typedef struct {
    uint16_t source_id;              /* Node ID this tracker belongs to */
    uint32_t highest_seen_seq;       /* Highest sequence number seen from this source */
    uint64_t window_bits;            /* Sliding window bitmask for recent sequences */
} replay_tracker_t;

/* Public API */

int packet_init(uint16_t our_node_id);

int packet_create(
    packet_t* packet,
    uint16_t dest_id,
    uint8_t type,
    const uint8_t* payload,
    size_t payload_len);

int packet_encrypt(packet_t* packet, const uint8_t* key);
int packet_decrypt(packet_t* packet, const uint8_t* key);

int packet_serialize(const packet_t* packet, uint8_t* buffer, size_t buffer_size);
int packet_deserialize(const uint8_t* buffer, size_t buffer_len, packet_t* packet);

int packet_handle(const packet_t* packet, uint16_t from_node);

int packet_seen_before(uint16_t source, uint32_t sequence);
int packet_add_to_cache(uint16_t source, uint32_t sequence, uint16_t from_node);

int packet_is_replay(uint16_t source, uint32_t seq);

#endif /* PACKET_H */
