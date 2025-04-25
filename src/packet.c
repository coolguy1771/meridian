#include "packet.h"
#include "security.h"
#include <string.h>

/* Maximum number of recently seen packets to track */
#define RECENT_PACKET_CACHE_SIZE 64

/* Global state */
static struct {
    uint16_t our_node_id;
    uint16_t tx_sequence;
    recent_packet_t recent_packets[RECENT_PACKET_CACHE_SIZE];
    uint16_t recent_head;
} packet_state;

/**
 * Initialize the packet handling system
 */
int packet_init(uint16_t our_node_id) {
    packet_state.our_node_id = our_node_id;
    packet_state.tx_sequence = 0;
    packet_state.recent_head = 0;
    
    /* Clear the recent packet cache */
    memset(packet_state.recent_packets, 0, sizeof(packet_state.recent_packets));
    
    return 0;
}

/**
 * Create a new packet with the given parameters
 */
int packet_create(
    packet_t* packet,
    uint16_t dest_id,
    uint8_t type,
    const uint8_t* payload,
    size_t payload_len)
{
    if (!packet || !payload || payload_len > MAX_PAYLOAD_SIZE) {
        return -1;
    }
    
    /* Fill in the header */
    packet->header.destination = dest_id;
    packet->header.source = packet_state.our_node_id;
    packet->header.type = type;
    packet->header.ttl = (dest_id == BROADCAST_ADDR) ? 3 : 5; /* Default TTL values */
    packet->header.sequence = packet_state.tx_sequence++;
    packet->header.band_info = 0; /* Will be set by radio layer */
    packet->header.multi_band_flags = 0;
    packet->header.nonce_fragment = 0; /* Will be set during encryption */
    
    /* Copy the payload */
    memcpy(packet->payload, payload, payload_len);
    packet->payload_len = payload_len;
    
    /* Tag will be set during encryption */
    memset(packet->tag, 0, sizeof(packet->tag));
    
    return 0;
}

/**
 * Encrypt a packet's payload
 */
int packet_encrypt(packet_t* packet, const uint8_t* key) {
    if (!packet || !key) {
        return -1;
    }
    
    /* Create a nonce for this packet */
    secure_nonce_t nonce;
    if (security_get_next_nonce(&nonce) != 0) {
        return -2;
    }
    
    /* Store the lower 16 bits of counter as nonce fragment in the header */
    packet->header.nonce_fragment = (uint16_t)(nonce.counter & 0xFFFF);
    
    /* Use the header as associated data for authenticated encryption */
    uint8_t ciphertext[MAX_PAYLOAD_SIZE];
    
    int result = security_encrypt(
        key,
        &nonce,
        packet->payload,
        packet->payload_len,
        (uint8_t*)&packet->header,
        sizeof(packet_header_t),
        ciphertext,
        packet->tag
    );
    
    if (result < 0) {
        return result;
    }
    
    /* Replace plaintext with ciphertext */
    memcpy(packet->payload, ciphertext, packet->payload_len);
    
    return 0;
}

/**
 * Decrypt a packet's payload
 */
int packet_decrypt(packet_t* packet, const uint8_t* key) {
    if (!packet || !key) {
        return -1;
    }
    
    /* Reconstruct the nonce from header information */
    secure_nonce_t nonce;
    memcpy(nonce.node_id, &packet->header.source, sizeof(uint16_t));
    memset(nonce.node_id + sizeof(uint16_t), 0, sizeof(uint16_t));
    nonce.counter = packet->header.nonce_fragment; /* Only the lower 16 bits */
    nonce.random = 0; /* We don't have this information, but it's not critical */
    
    /* Decrypt using the header as associated data */
    uint8_t plaintext[MAX_PAYLOAD_SIZE];
    
    int result = security_decrypt(
        key,
        &nonce,
        packet->payload,
        packet->payload_len,
        (uint8_t*)&packet->header,
        sizeof(packet_header_t),
        packet->tag,
        plaintext
    );
    
    if (result < 0) {
        return result;
    }
    
    /* Replace ciphertext with plaintext */
    memcpy(packet->payload, plaintext, packet->payload_len);
    
    return 0;
}

/**
 * Serialize a packet to a byte buffer for transmission
 */
int packet_serialize(
    const packet_t* packet,
    uint8_t* buffer,
    size_t buffer_size)
{
    if (!packet || !buffer) {
        return -1;
    }
    
    /* Calculate total packet size */
    size_t total_size = sizeof(packet_header_t) + packet->payload_len + sizeof(packet->tag);
    
    if (buffer_size < total_size) {
        return -2;
    }
    
    /* Copy header */
    memcpy(buffer, &packet->header, sizeof(packet_header_t));
    
    /* Copy payload */
    memcpy(buffer + sizeof(packet_header_t), packet->payload, packet->payload_len);
    
    /* Copy tag */
    memcpy(buffer + sizeof(packet_header_t) + packet->payload_len, 
           packet->tag, sizeof(packet->tag));
    
    return total_size;
}

/**
 * Deserialize a byte buffer into a packet structure
 */
int packet_deserialize(
    const uint8_t* buffer,
    size_t buffer_len,
    packet_t* packet)
{
    if (!buffer || !packet || buffer_len < sizeof(packet_header_t)) {
        return -1;
    }
    
    /* Copy header */
    memcpy(&packet->header, buffer, sizeof(packet_header_t));
    
    /* Calculate payload length (total - header - tag) */
    size_t payload_len = buffer_len - sizeof(packet_header_t) - sizeof(packet->tag);
    
    if (payload_len > MAX_PAYLOAD_SIZE || buffer_len < sizeof(packet_header_t) + payload_len + sizeof(packet->tag)) {
        return -2;
    }
    
    /* Copy payload */
    memcpy(packet->payload, buffer + sizeof(packet_header_t), payload_len);
    packet->payload_len = payload_len;
    
    /* Copy tag */
    memcpy(packet->tag, buffer + sizeof(packet_header_t) + payload_len, sizeof(packet->tag));
    
    return 0;
}

/**
 * Handle a received packet (forwarding logic)
 */
int packet_handle(const packet_t* packet, uint16_t from_node) {
    if (!packet) {
        return -1;
    }
    
    /* Check if this is for us or broadcast */
    if (packet->header.destination == packet_state.our_node_id || 
        packet->header.destination == BROADCAST_ADDR) {
        /* Process the packet locally */
        /* This function just determines routing, actual processing happens elsewhere */
        
        /* Add to seen cache to avoid duplicate processing */
        packet_add_to_cache(packet->header.source, packet->header.sequence, from_node);
        
        /* If it's a broadcast and TTL > 0, we should also forward it */
        if (packet->header.destination == BROADCAST_ADDR && packet->header.ttl > 0) {
            /* Return 2 to indicate "for us AND forward" */
            return 2;
        }
        
        /* Return 0 to indicate "for us, don't forward" */
        return 0;
    }
    
    /* Not for us, check if we should forward it */
    if (packet->header.ttl > 0 && !packet_seen_before(packet->header.source, packet->header.sequence)) {
        /* Add to seen cache */
        packet_add_to_cache(packet->header.source, packet->header.sequence, from_node);
        
        /* Return 1 to indicate "not for us, forward" */
        return 1;
    }
    
    /* Not for us and should not forward */
    return -2;
}

/**
 * Check if we've seen this packet before
 */
int packet_seen_before(uint16_t source, uint16_t sequence) {
    for (int i = 0; i < RECENT_PACKET_CACHE_SIZE; i++) {
        if (packet_state.recent_packets[i].source == source &&
            packet_state.recent_packets[i].sequence == sequence) {
            return 1;
        }
    }
    return 0;
}

/**
 * Add a packet to the seen cache
 */
int packet_add_to_cache(uint16_t source, uint16_t sequence, uint16_t from_node) {
    /* Use a ring buffer approach */
    packet_state.recent_packets[packet_state.recent_head].source = source;
    packet_state.recent_packets[packet_state.recent_head].sequence = sequence;
    packet_state.recent_packets[packet_state.recent_head].from_node = from_node;
    packet_state.recent_packets[packet_state.recent_head].timestamp = 0; /* TODO: Get system time */
    
    /* Move to next position */
    packet_state.recent_head = (packet_state.recent_head + 1) % RECENT_PACKET_CACHE_SIZE;
    
    return 0;
}