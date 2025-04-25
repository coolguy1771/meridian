#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "packet.h"
#include "security.h"
#include "platform.h"

/* Test cases */
static int test_init(void);
static int test_create_packet(void);
static int test_serialize_deserialize(void);
static int test_packet_handling(void);
static int test_seen_cache(void);

int main(void) {
    printf("Testing Packet Module\n");
    
    /* Initialize platform */
    platform_init();
    
    int failed = 0;
    
    printf("Test 1: Initialization... ");
    if (test_init() == 0) {
        printf("PASSED\n");
    } else {
        printf("FAILED\n");
        failed++;
    }
    
    printf("Test 2: Packet creation... ");
    if (test_create_packet() == 0) {
        printf("PASSED\n");
    } else {
        printf("FAILED\n");
        failed++;
    }
    
    printf("Test 3: Serialization/deserialization... ");
    if (test_serialize_deserialize() == 0) {
        printf("PASSED\n");
    } else {
        printf("FAILED\n");
        failed++;
    }
    
    printf("Test 4: Packet handling... ");
    if (test_packet_handling() == 0) {
        printf("PASSED\n");
    } else {
        printf("FAILED\n");
        failed++;
    }
    
    printf("Test 5: Seen cache... ");
    if (test_seen_cache() == 0) {
        printf("PASSED\n");
    } else {
        printf("FAILED\n");
        failed++;
    }
    
    printf("\nTest summary: %d tests, %d passed, %d failed\n", 5, 5 - failed, failed);
    
    return failed ? 1 : 0;
}

/* Test initialization */
static int test_init(void) {
    /* Initialize with valid node ID */
    if (packet_init(0x1234) != 0) {
        return -1;
    }
    
    return 0;
}

/* Test packet creation */
static int test_create_packet(void) {
    packet_t packet;
    uint8_t payload[] = "Test payload";
    size_t payload_len = strlen((char*)payload);
    
    /* Initialize */
    if (packet_init(0x1234) != 0) {
        return -1;
    }
    
    /* Create a packet */
    if (packet_create(&packet, 0x5678, PACKET_TYPE_VOICE, payload, payload_len) != 0) {
        return -2;
    }
    
    /* Verify header fields */
    if (packet.header.destination != 0x5678) {
        return -3;
    }
    
    if (packet.header.source != 0x1234) {
        return -4;
    }
    
    if (packet.header.type != PACKET_TYPE_VOICE) {
        return -5;
    }
    
    if (packet.header.ttl != 5) {
        return -6; /* Default TTL for unicast should be 5 */
    }
    
    /* Verify payload */
    if (packet.payload_len != payload_len) {
        return -7;
    }
    
    if (memcmp(packet.payload, payload, payload_len) != 0) {
        return -8;
    }
    
    /* Test broadcast packet */
    if (packet_create(&packet, BROADCAST_ADDR, PACKET_TYPE_BEACON, payload, payload_len) != 0) {
        return -9;
    }
    
    /* Verify broadcast TTL */
    if (packet.header.ttl != 3) {
        return -10; /* Default TTL for broadcast should be 3 */
    }
    
    /* Test invalid payload length */
    if (packet_create(&packet, 0x5678, PACKET_TYPE_VOICE, payload, MAX_PAYLOAD_SIZE + 1) == 0) {
        return -11; /* Should fail with too large payload */
    }
    
    return 0;
}

/* Test packet serialization/deserialization */
static int test_serialize_deserialize(void) {
    packet_t packet1, packet2;
    uint8_t payload[] = "Test payload for serialization";
    size_t payload_len = strlen((char*)payload);
    uint8_t buffer[MAX_PACKET_SIZE];
    size_t buffer_len;
    
    /* Initialize */
    if (packet_init(0x1234) != 0) {
        return -1;
    }
    
    /* Create a packet */
    if (packet_create(&packet1, 0x5678, PACKET_TYPE_VOICE, payload, payload_len) != 0) {
        return -2;
    }
    
    /* Set some tag bytes for testing */
    memset(packet1.tag, 0xAA, sizeof(packet1.tag));
    
    /* Serialize the packet */
    buffer_len = packet_serialize(&packet1, buffer, sizeof(buffer));
    if (buffer_len <= 0) {
        return -3;
    }
    
    /* Verify buffer length */
    if (buffer_len != sizeof(packet_header_t) + payload_len + sizeof(packet1.tag)) {
        return -4;
    }
    
    /* Deserialize the packet */
    if (packet_deserialize(buffer, buffer_len, &packet2) != 0) {
        return -5;
    }
    
    /* Verify header fields match */
    if (packet2.header.destination != packet1.header.destination ||
        packet2.header.source != packet1.header.source ||
        packet2.header.type != packet1.header.type ||
        packet2.header.ttl != packet1.header.ttl ||
        packet2.header.sequence != packet1.header.sequence) {
        return -6;
    }
    
    /* Verify payload */
    if (packet2.payload_len != packet1.payload_len) {
        return -7;
    }
    
    if (memcmp(packet2.payload, packet1.payload, packet1.payload_len) != 0) {
        return -8;
    }
    
    /* Verify tag */
    if (memcmp(packet2.tag, packet1.tag, sizeof(packet1.tag)) != 0) {
        return -9;
    }
    
    /* Test invalid buffer length */
    if (packet_deserialize(buffer, 5, &packet2) == 0) {
        return -10; /* Should fail with too small buffer */
    }
    
    return 0;
}

/* Test packet handling */
static int test_packet_handling(void) {
    packet_t packet;
    uint8_t payload[] = "Test payload for handling";
    size_t payload_len = strlen((char*)payload);
    
    /* Initialize with node ID 0x1234 */
    if (packet_init(0x1234) != 0) {
        return -1;
    }
    
    /* Create a packet for us */
    if (packet_create(&packet, 0x1234, PACKET_TYPE_VOICE, payload, payload_len) != 0) {
        return -2;
    }
    
    /* Handle packet - should be for us */
    int result = packet_handle(&packet, 0);
    if (result != 0) {
        return -3;
    }
    
    /* Create a packet for someone else */
    if (packet_create(&packet, 0x5678, PACKET_TYPE_VOICE, payload, payload_len) != 0) {
        return -4;
    }
    
    /* Handle packet - should be forwarded */
    result = packet_handle(&packet, 0);
    if (result != 1) {
        return -5;
    }
    
    /* Create a broadcast packet */
    if (packet_create(&packet, BROADCAST_ADDR, PACKET_TYPE_BEACON, payload, payload_len) != 0) {
        return -6;
    }
    
    /* Handle packet - should be for us AND forwarded */
    result = packet_handle(&packet, 0);
    if (result != 2) {
        return -7;
    }
    
    /* Modify TTL to 0 */
    packet.header.ttl = 0;
    
    /* Handle packet - should be for us but NOT forwarded */
    result = packet_handle(&packet, 0);
    if (result != 0) {
        return -8;
    }
    
    return 0;
}

/* Test seen cache */
static int test_seen_cache(void) {
    packet_t packet;
    uint8_t payload[] = "Test payload for cache";
    size_t payload_len = strlen((char*)payload);
    
    /* Initialize */
    if (packet_init(0x1234) != 0) {
        return -1;
    }
    
    /* Check that nothing is in cache yet */
    if (packet_seen_before(0x5678, 123) != 0) {
        return -2;
    }
    
    /* Add to cache */
    if (packet_add_to_cache(0x5678, 123, 0x9ABC) != 0) {
        return -3;
    }
    
    /* Check that it's now in cache */
    if (packet_seen_before(0x5678, 123) != 1) {
        return -4;
    }
    
    /* Check that different sequence is not in cache */
    if (packet_seen_before(0x5678, 124) != 0) {
        return -5;
    }
    
    /* Check that different source is not in cache */
    if (packet_seen_before(0x9ABC, 123) != 0) {
        return -6;
    }
    
    /* Create a packet */
    if (packet_create(&packet, 0x5678, PACKET_TYPE_VOICE, payload, payload_len) != 0) {
        return -7;
    }
    
    /* Handle packet - should be forwarded */
    int result = packet_handle(&packet, 0);
    if (result != 1) {
        return -8;
    }
    
    /* Handle same packet again - should NOT be forwarded (already seen) */
    result = packet_handle(&packet, 0);
    if (result == 1) {
        return -9;
    }
    
    return 0;
}