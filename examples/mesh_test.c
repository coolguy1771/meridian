#include <stdio.h>
#include <string.h>
#include "platform.h"
#include "security.h"
#include "packet.h"
#include "mesh.h"

static const uint16_t OUR_NODE_ID = 0x0001;

int main(void) {
    printf("=== Meridian Mesh Test ===\n");

    /* Initialize platform and security */
    if (platform_init() != 0) {
        fprintf(stderr, "Platform init failed\n");
        return 1;
    }

    if (security_init(SECURITY_E2E_AUTH, CIPHER_XCHACHA20_POLY) != 0) {
        fprintf(stderr, "Security init failed\n");
        return 1;
    }

    /* Initialize packet layer */
    if (packet_init(OUR_NODE_ID) != 0) {
        fprintf(stderr, "Packet init failed\n");
        return 1;
    }

    printf("Initialized node %04X\n", OUR_NODE_ID);

    /* Test creating and encrypting a text message */
    const char *msg = "Hello from Meridian!";
    packet_t pkt;

    if (packet_create(&pkt, 0x0002, PACKET_TYPE_TEXT,
                      (uint8_t*)msg, strlen(msg)) != 0) {
        fprintf(stderr, "Packet creation failed\n");
        return 1;
    }

    /* Use a test session key for this demo */
    uint8_t session_key[SYMMETRIC_KEY_LENGTH];
    randombytes_buf(session_key, SYMMETRIC_KEY_LENGTH);

    if (packet_encrypt(&pkt, session_key) != 0) {
        fprintf(stderr, "Packet encryption failed\n");
        return 1;
    }

    printf("Created and encrypted text packet to node %04X\n", pkt.header.destination);

    /* Serialize the packet */
    uint8_t buffer[MAX_PACKET_SIZE];
    int ser_len = packet_serialize(&pkt, buffer, sizeof(buffer));
    if (ser_len <= 0) {
        fprintf(stderr, "Packet serialization failed: %d\n", ser_len);
        return 1;
    }

    printf("Serialized packet length: %d bytes\n", ser_len);
    printf("Header: dst=%04X src=%04X type=0x%02X ttl=%u seq=%u nonce=0x%llX\n",
           pkt.header.destination, pkt.header.source, pkt.header.type,
           pkt.header.ttl, pkt.header.sequence,
           (unsigned long long)pkt.header.nonce_value);

    /* Deserialize and decrypt */
    packet_t received;
    if (packet_deserialize(buffer, ser_len, &received) != 0) {
        fprintf(stderr, "Deserialization failed\n");
        return 1;
    }

    if (packet_decrypt(&received, session_key) != 0) {
        fprintf(stderr, "Decryption failed\n");
        return 1;
    }

    printf("Decrypted payload: %.*s\n", (int)received.payload_len, received.payload);

    /* Test handshake flow simulation */
    printf("\n--- Handshake Simulation ---\n");

    uint8_t eph_pub[PUBLIC_KEY_LENGTH], eph_priv[PRIVATE_KEY_LENGTH];
    crypto_box_keypair(eph_pub, eph_priv);

    handshake_message_t hello;
    memset(&hello, 0, sizeof(hello));
    hello.type = HANDSHAKE_TYPE_HELLO;
    hello.initiator_id = OUR_NODE_ID;
    hello.responder_id = 0x0002;
    memcpy(hello.public_key, eph_pub, PUBLIC_KEY_LENGTH);

    /* Store responder identity keys for simulation */
    uint8_t resp_pub[PUBLIC_KEY_LENGTH], resp_priv[PRIVATE_KEY_LENGTH];
    crypto_box_keypair(resp_pub, resp_priv);
    security_store_identity_keys(resp_pub, resp_priv);

    /* Switch to responder perspective temporarily by storing its keys */
    /* For this test we simulate by calling process_handshake directly */

    uint8_t orig_pub[PUBLIC_KEY_LENGTH], orig_priv[PRIVATE_KEY_LENGTH];
    security_load_identity_keys(orig_pub, orig_priv);

    /* Act as responder processing HELLO */
    security_store_identity_keys(resp_pub, resp_priv);
    handshake_message_t response;
    int rc = security_process_handshake(&hello, 0x0002, &response);
    if (rc != 0 || response.type != HANDSHAKE_TYPE_RESPONSE) {
        fprintf(stderr, "Handshake RESPONSE failed: %d\n", rc);
        security_store_identity_keys(orig_pub, orig_priv);
        return 1;
    }

    printf("Handshake RESPONSE from node %04X\n", response.responder_id);

    /* Restore initiator keys and confirm */
    security_store_identity_keys(orig_pub, orig_priv);

    handshake_message_t confirm;
    /* Simulate responder sending its ephemeral in the response (simplified) */
    uint8_t resp_eph[PUBLIC_KEY_LENGTH], resp_eph_priv[PRIVATE_KEY_LENGTH];
    crypto_box_keypair(resp_eph, resp_eph_priv);
    memcpy(response.public_key, resp_eph, PUBLIC_KEY_LENGTH);

    rc = security_process_handshake(&response, OUR_NODE_ID, &confirm);
    if (rc != 0 || confirm.type != HANDSHAKE_TYPE_CONFIRM) {
        fprintf(stderr, "Handshake CONFIRM failed: %d\n", rc);
        return 1;
    }

    /* Verify we can look up the session key before assuming success */
    uint8_t derived_key[SYMMETRIC_KEY_LENGTH];
    rc = security_get_session_key(confirm.responder_id, derived_key);
    if (rc != 0) {
        fprintf(stderr, "Session established but key lookup failed for %04X: %d\n", confirm.responder_id, rc);
        return 1;
    }

    printf("Session established with node %04X\n", confirm.responder_id);

    printf("Session key length: %zu bytes\n", SYMMETRIC_KEY_LENGTH);
    printf("First 4 bytes of session key: %02X %02X %02X %02X\n",
           derived_key[0], derived_key[1], derived_key[2], derived_key[3]);

    sodium_memzero(session_key, sizeof(session_key));
    sodium_memzero(eph_priv, sizeof(eph_priv));
    sodium_memzero(resp_priv, sizeof(resp_priv));
    sodium_memzero(orig_priv, sizeof(orig_priv));
    sodium_memzero(resp_eph_priv, sizeof(resp_eph_priv));
    sodium_memzero(derived_key, sizeof(derived_key));

    printf("\n=== All mesh tests passed ===\n");
    return 0;
}
