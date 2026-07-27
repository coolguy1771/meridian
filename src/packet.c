#include "packet.h"
#include "security.h"
#include "platform.h"
#include <string.h>

/* Cache sizes */
#define RECENT_PACKET_CACHE_SIZE 128   /* Recently seen (src,seq) pairs */
#define REPLAY_TRACKERS_MAX      32    /* Per-source replay windows we track */

/* Global state */
static struct {
    uint16_t our_node_id;
    uint32_t tx_sequence;               /* Our transmit sequence counter */
    recent_packet_t recent_packets[RECENT_PACKET_CACHE_SIZE];
    uint16_t recent_head;

    /* Per-source sliding-window replay protection */
    replay_tracker_t replay_trackers[REPLAY_TRACKERS_MAX];
    uint8_t replay_initialized;         /* Whether trackers are initialized */
} packet_state;

/**
 * Initializes packet state for the specified node and restores the transmit sequence from persistent storage when available.
 *
 * @param our_node_id Identifier of the local node.
 * @returns 0 on success.
 */

int packet_init(uint16_t our_node_id) {
    packet_state.our_node_id = our_node_id;
    packet_state.tx_sequence = 0;
    packet_state.recent_head = 0;
    memset(packet_state.recent_packets, 0, sizeof(packet_state.recent_packets));
    memset(packet_state.replay_trackers, 0, sizeof(packet_state.replay_trackers));
    packet_state.replay_initialized = 1;

    /* Try to restore tx_sequence from a simple persistent slot */
    uint32_t stored_seq = 0;
    platform_flash_read(0x70000, &stored_seq, sizeof(stored_seq));
    if (stored_seq > 0) {
        packet_state.tx_sequence = stored_seq;
    }

    return 0;
}

/**
 * Initializes a packet with destination, source, type, routing, sequence, and payload data.
 *
 * @param packet Packet to initialize.
 * @param dest_id Destination node identifier.
 * @param type Packet type.
 * @param payload Payload data to copy into the packet.
 * @param payload_len Number of payload bytes.
 * @return 0 on success, or -1 if an argument is invalid or the payload exceeds MAX_PAYLOAD_SIZE.
 */

int packet_create(packet_t* packet, uint16_t dest_id, uint8_t type,
                  const uint8_t* payload, size_t payload_len) {
    if (!packet || !payload || payload_len > MAX_PAYLOAD_SIZE) {
        return -1;
    }

    packet->header.destination = dest_id;
    packet->header.source = packet_state.our_node_id;
    packet->header.type = type;
    packet->header.ttl = (dest_id == BROADCAST_ADDR) ? 3 : MAX_TTL;
    packet->header.sequence = packet_state.tx_sequence++;
    packet->header.nonce_value = 0; /* Set during encryption */

    memcpy(packet->payload, payload, payload_len);
    packet->payload_len = payload_len;
    memset(packet->tag, 0, sizeof(packet->tag));

    return 0;
}

/**
 * Encrypts a packet payload and authenticates its header and resulting ciphertext.
 *
 * @param packet Packet whose payload and authentication tag are updated.
 * @param key Encryption key.
 * @returns 0 on success; -1 for invalid arguments, -2 if a nonce cannot be obtained, or a negative encryption error code.
 */
int packet_encrypt(packet_t* packet, const uint8_t* key) {
    if (!packet || !key) {
        return -1;
    }

    secure_nonce_t nonce;
    if (security_get_next_nonce(&nonce) != 0) {
        return -2;
    }

    /* Store full nonce in header so receiver can reconstruct exact same value */
    packet->header.nonce_value = nonce.value;

    uint8_t ciphertext[MAX_PAYLOAD_SIZE];

    /* AAD: authenticate non-mutable parts of the header only.
     * Mutable fields must be excluded because relays may change them:
     *   - ttl: decremented by each hop when forwarding a packet.
     * Binding nonce_value + addressing fields is correct; ttl is intentionally omitted. */
    uint8_t aad_buf[sizeof(packet_header_t)];
    memcpy(aad_buf, &packet->header, sizeof(packet_header_t));
    memset(aad_buf + offsetof(packet_header_t, ttl), 0, sizeof(uint8_t));

    int result = security_encrypt(
        key, &nonce,
        packet->payload, packet->payload_len,
        aad_buf, sizeof(aad_buf),
        ciphertext, packet->tag);

    if (result < 0) {
        return result;
    }

    memcpy(packet->payload, ciphertext, packet->payload_len);

    /* Persist tx sequence every N packets to recover after reboot */
    if (packet_state.tx_sequence % 1024 == 0) {
        platform_flash_write(0x70000, &packet_state.tx_sequence, sizeof(uint32_t));
    }

    return 0;
}

/**
 * Decrypts and authenticates a packet payload.
 *
 * @param packet Packet containing the encrypted payload, nonce, and authentication tag.
 * @param key Key used to decrypt and authenticate the payload.
 * @returns 0 on success, -1 for invalid arguments, or a negative decryption error code.
 */
int packet_decrypt(packet_t* packet, const uint8_t* key) {
    if (!packet || !key) {
        return -1;
    }

    /* Recreate nonce from transmitted header value */
    secure_nonce_t nonce;
    nonce.value = packet->header.nonce_value;

    uint8_t plaintext[MAX_PAYLOAD_SIZE];

    /* AAD: match the encryption-side logic by zeroing out mutable ttl field. */
    uint8_t aad_buf[sizeof(packet_header_t)];
    memcpy(aad_buf, &packet->header, sizeof(packet_header_t));
    memset(aad_buf + offsetof(packet_header_t, ttl), 0, sizeof(uint8_t));

    int result = security_decrypt(
        key, &nonce,
        packet->payload, packet->payload_len,
        aad_buf, sizeof(aad_buf),
        packet->tag, plaintext);

    if (result < 0) {
        return result;
    }

    memcpy(packet->payload, plaintext, packet->payload_len);
    return 0;
}

/**
 * Serializes a packet into a caller-provided buffer.
 *
 * @param buffer_size Capacity of the output buffer in bytes.
 * @return The number of bytes written, -1 for invalid pointers, or -2 when the buffer is too small.
 */
int packet_serialize(const packet_t* packet, uint8_t* buffer, size_t buffer_size) {
    if (!packet || !buffer) {
        return -1;
    }

    size_t total = sizeof(packet_header_t) + packet->payload_len + sizeof(packet->tag);
    if (buffer_size < total) {
        return -2; /* Buffer too small */
    }

    memcpy(buffer, &packet->header, sizeof(packet_header_t));
    memcpy(buffer + sizeof(packet_header_t), packet->payload, packet->payload_len);
    memcpy(buffer + sizeof(packet_header_t) + packet->payload_len,
           packet->tag, sizeof(packet->tag));
    return (int)total;
}

/**
 * Deserializes a packet from a contiguous buffer.
 *
 * @param buffer Serialized packet data.
 * @param buffer_len Length of the serialized packet data in bytes.
 * @param packet Packet structure to populate.
 * @return 0 on success; -1 for invalid arguments or an incomplete header,
 *         -2 for insufficient data for the header and authentication tag,
 *         or -3 for an invalid payload length.
 */
int packet_deserialize(const uint8_t* buffer, size_t buffer_len, packet_t* packet) {
    if (!buffer || !packet || buffer_len < sizeof(packet_header_t)) {
        return -1;
    }

    memcpy(&packet->header, buffer, sizeof(packet_header_t));

    size_t total_overhead = sizeof(packet_header_t) + sizeof(packet->tag);
    if (buffer_len < total_overhead) {
        return -2;
    }

    size_t payload_len = buffer_len - total_overhead;
    if (payload_len > MAX_PAYLOAD_SIZE || payload_len == 0) {
        return -3;
    }

    memcpy(packet->payload, buffer + sizeof(packet_header_t), payload_len);
    packet->payload_len = payload_len;
    memcpy(packet->tag, buffer + sizeof(packet_header_t) + payload_len, sizeof(packet->tag));

    return 0;
}

/**
 * Finds or creates replay-tracking state for a source node.
 *
 * @param source_id Source node identifier.
 * @param out_idx Receives the tracker index.
 * @return 0 on success.
 */

static int find_or_create_replay_tracker(uint16_t source_id, int* out_idx) {
    /* Find existing tracker */
    for (int i = 0; i < REPLAY_TRACKERS_MAX; i++) {
        if (packet_state.replay_trackers[i].source_id == source_id) {
            *out_idx = i;
            return 0;
        }
    }

    /* Find empty slot */
    for (int i = 0; i < REPLAY_TRACKERS_MAX; i++) {
        if (packet_state.replay_trackers[i].source_id == 0) {
            packet_state.replay_trackers[i].source_id = source_id;
            packet_state.replay_trackers[i].highest_seen_seq = 0;
            packet_state.replay_trackers[i].window_bits = 0ULL;
            *out_idx = i;
            return 0;
        }
    }

    /* Table full: evict oldest (lowest highest_seen_seq) */
    int evict = 0;
    uint32_t min_seq = packet_state.replay_trackers[0].highest_seen_seq + 1;
    for (int i = 1; i < REPLAY_TRACKERS_MAX; i++) {
        if (packet_state.replay_trackers[i].highest_seen_seq + 1 < min_seq) {
            min_seq = packet_state.replay_trackers[i].highest_seen_seq + 1;
            evict = i;
        }
    }

    packet_state.replay_trackers[evict].source_id = source_id;
    packet_state.replay_trackers[evict].highest_seen_seq = 0;
    packet_state.replay_trackers[evict].window_bits = 0ULL;
    *out_idx = evict;
    return 0;
}

/**
 * Determines whether a sequence number has already been accepted for a source.
 *
 * @param source Source node identifier.
 * @param seq Sequence number to evaluate.
 * @return 1 if the sequence is stale or was previously accepted, 0 otherwise.
 */
int packet_is_replay(uint16_t source, uint32_t seq) {
    if (!packet_state.replay_initialized || source == 0) {
        return 0; /* No replay tracking yet */
    }

    int idx;
    if (find_or_create_replay_tracker(source, &idx) != 0) {
        return 0;
    }

    replay_tracker_t* tr = &packet_state.replay_trackers[idx];

    /* Sequence ahead of highest seen: accept and advance window */
    if (seq > tr->highest_seen_seq) {
        uint32_t delta = seq - tr->highest_seen_seq;
        if (delta >= REPLAY_WINDOW_SIZE) {
            /* Big jump — reset window */
            tr->window_bits = 0ULL;
        } else {
            /* Shift window left, fill bits for newly accepted range.
             * Mask to avoid shifting beyond 64 bits when delta is small but close to limit. */
            uint64_t all_ones = (REPLAY_WINDOW_SIZE >= 64) ? ~0ULL : ((1ULL << REPLAY_WINDOW_SIZE) - 1);
            uint64_t new_bits_mask = (delta >= 64) ? 0ULL : ((1ULL << delta) - 1);
            tr->window_bits = (tr->window_bits << delta) & all_ones;
            tr->window_bits |= new_bits_mask & all_ones;
        }
        tr->highest_seen_seq = seq;
        return 0; /* Not a replay */
    }

    /* Sequence behind: check if already in window */
    uint32_t age = tr->highest_seen_seq - seq;
    if (age >= REPLAY_WINDOW_SIZE) {
        return 1; /* Too old — likely stale/replay */
    }

    uint64_t bit = 1ULL << age;
    if (tr->window_bits & bit) {
        return 1; /* Already seen in window -> replay */
    }

    tr->window_bits |= bit;
    return 0; /* New within window */
}

/**
 * Determines whether a packet should be delivered locally, forwarded, or ignored.
 *
 * @param packet Packet to evaluate.
 * @param from_node Node from which the packet was received.
 * @returns 0 if the packet is for this node only, 1 if it should be forwarded,
 *          2 if it should be delivered locally and forwarded, -1 if packet is
 *          NULL, or -2 if the packet is a duplicate or has expired.
 */

int packet_handle(const packet_t* packet, uint16_t from_node) {
    if (!packet) {
        return -1;
    }

    /* Check for broadcast or direct-to-us */
    int for_us = (packet->header.destination == packet_state.our_node_id ||
                  packet->header.destination == BROADCAST_ADDR);

    uint32_t seq = packet->header.sequence; /* Cache this for reuse below */

    if (for_us) {
        /* Add to seen cache using seq declared above */
        packet_add_to_cache(packet->header.source, seq, from_node);

        /* For broadcast with TTL>0: deliver locally AND forward */
        if (packet->header.destination == BROADCAST_ADDR && packet->header.ttl > 0) {
            return 2; /* For us AND should forward */
        }
        return 0; /* Only for us */
    }

    /* Not for us — should we relay? */
    if (packet->header.ttl > 0 && !packet_seen_before(packet->header.source, seq)) {
        packet_add_to_cache(packet->header.source, seq, from_node);
        return 1; /* Forward only */
    }

    return -2; /* Don't handle (duplicate or TTL expired) */
}

/**
 * Determines whether a packet from a source and sequence has been recently seen.
 * @param source Packet source identifier.
 * @param sequence Packet sequence number.
 * @returns `1` if a matching packet is cached, `0` otherwise.
 */
int packet_seen_before(uint16_t source, uint32_t sequence) {
    for (int i = 0; i < RECENT_PACKET_CACHE_SIZE; i++) {
        if (packet_state.recent_packets[i].source == source &&
            packet_state.recent_packets[i].sequence == sequence) {
            return 1;
        }
    }
    return 0;
}

/**
 * Adds a packet identifier and forwarding source to the recent-packet cache.
 *
 * @param source Packet source node identifier.
 * @param sequence Packet sequence number.
 * @param from_node Node from which the packet was received.
 * @return 0 on success.
 */
int packet_add_to_cache(uint16_t source, uint32_t sequence, uint16_t from_node) {
    recent_packet_t* entry = &packet_state.recent_packets[packet_state.recent_head];
    entry->source = source;
    entry->sequence = sequence;
    entry->from_node = from_node;
    entry->timestamp = platform_get_time_ms();

    packet_state.recent_head = (packet_state.recent_head + 1) % RECENT_PACKET_CACHE_SIZE;
    return 0;
}
