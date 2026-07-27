#include <stdio.h>
#include <string.h>
#include "platform.h"
#include "security.h"
#include "packet.h"

/* Example: Voice chat over Meridian mesh using Codec2-style payload packaging.
 * This example focuses on the crypto/security plumbing; actual Codec2 encode/decode
 * would be integrated in a production build with -DUSE_CODEC2=ON. */

#define OUR_NODE_ID   0x1001
#define PEER_NODE_ID  0x1002

/**
 * Demonstrates an encrypted voice packet exchange between two simulated nodes.
 *
 * @return 0 if the demonstration completes successfully, or 1 if initialization,
 *         handshake, session-key, packet, serialization, or decryption processing fails.
 */
int main(void) {
    printf("Meridian Voice Chat Demo (Codec2 stub + security)\n");

    if (platform_init() != 0 || security_init(SECURITY_E2E_AUTH, CIPHER_XCHACHA20_POLY) != 0) {
        fprintf(stderr, "Init failed\n");
        return 1;
    }

    packet_init(OUR_NODE_ID);

    /* Create a sample voice payload stub (in production this would be Codec2 frames) */
    uint8_t voice_frame[128];
    memset(voice_frame, 0x42, sizeof(voice_frame)); /* Dummy data */

    /* Establish session with peer via handshake simulation */
    uint8_t eph_pub[PUBLIC_KEY_LENGTH], eph_priv[PRIVATE_KEY_LENGTH];
    crypto_box_keypair(eph_pub, eph_priv);

    uint8_t peer_pub[PUBLIC_KEY_LENGTH], peer_priv[PRIVATE_KEY_LENGTH];
    crypto_box_keypair(peer_pub, peer_priv);

    /* Store our identity keys */
    security_store_identity_keys(eph_pub, eph_priv);

    handshake_message_t hello;
    memset(&hello, 0, sizeof(hello));
    hello.type = HANDSHAKE_TYPE_HELLO;
    hello.initiator_id = OUR_NODE_ID;
    hello.responder_id = PEER_NODE_ID;
    memcpy(hello.public_key, eph_pub, PUBLIC_KEY_LENGTH);

    /* Simulate responder processing HELLO */
    security_store_identity_keys(peer_pub, peer_priv);
    handshake_message_t response;
    int rc = security_process_handshake(&hello, PEER_NODE_ID, &response);
    if (rc != 0 || response.type != HANDSHAKE_TYPE_RESPONSE) {
        fprintf(stderr, "Handshake failed\n");
        return 1;
    }

    /* Confirm on initiator side */
    uint8_t resp_eph[PUBLIC_KEY_LENGTH], resp_eph_priv[PRIVATE_KEY_LENGTH];
    crypto_box_keypair(resp_eph, resp_eph_priv);
    memcpy(response.public_key, resp_eph, PUBLIC_KEY_LENGTH);

    security_store_identity_keys(eph_pub, eph_priv);
    handshake_message_t confirm;
    rc = security_process_handshake(&response, OUR_NODE_ID, &confirm);
    if (rc != 0 || confirm.type != HANDSHAKE_TYPE_CONFIRM) {
        fprintf(stderr, "Handshake confirm failed\n");
        return 1;
    }

    printf("Voice session established with node %04X\n", PEER_NODE_ID);

    /* Now send encrypted voice frames */
    uint8_t frame_key[SYMMETRIC_KEY_LENGTH];
    rc = security_get_session_key(PEER_NODE_ID, frame_key);
    if (rc != 0) {
        fprintf(stderr, "No session key available\n");
        return 1;
    }

    packet_t pkt;
    if (packet_create(&pkt, PEER_NODE_ID, PACKET_TYPE_VOICE,
                      voice_frame, sizeof(voice_frame)) != 0) {
        /* Cleanup on failure */
        sodium_memzero(eph_priv, sizeof(eph_priv));
        sodium_memzero(peer_priv, sizeof(peer_priv));
        sodium_memzero(resp_eph_priv, sizeof(resp_eph_priv));
        fprintf(stderr, "Voice packet creation failed\n");
        return 1;
    }

    if (packet_encrypt(&pkt, frame_key) != 0) {
        sodium_memzero(frame_key, sizeof(frame_key));
        sodium_memzero(eph_priv, sizeof(eph_priv));
        sodium_memzero(peer_priv, sizeof(peer_priv));
        sodium_memzero(resp_eph_priv, sizeof(resp_eph_priv));
        fprintf(stderr, "Voice packet encryption failed\n");
        return 1;
    }

    uint8_t wire_buf[MAX_PACKET_SIZE];
    int len = packet_serialize(&pkt, wire_buf, sizeof(wire_buf));
    if (len <= 0) {
        sodium_memzero(frame_key, sizeof(frame_key));
        sodium_memzero(eph_priv, sizeof(eph_priv));
        sodium_memzero(peer_priv, sizeof(peer_priv));
        sodium_memzero(resp_eph_priv, sizeof(resp_eph_priv));
        fprintf(stderr, "Serialization failed\n");
        return 1;
    }

    printf("Voice frame encrypted and serialized: %d bytes on wire\n", len);

    /* Simulate decryption by the peer */
    uint8_t peer_key[SYMMETRIC_KEY_LENGTH];
    security_store_identity_keys(peer_pub, peer_priv);

    /* Re-derive session key from same handshake params */
    uint8_t shared[SHARED_SECRET_LENGTH];
    if (security_compute_shared_secret(eph_pub, shared) == 0) {
        security_derive_session_key(shared, PEER_NODE_ID, OUR_NODE_ID, peer_key);
    }

    packet_t recv_pkt;
    if (packet_deserialize(wire_buf, len, &recv_pkt) != 0) {
        sodium_memzero(frame_key, sizeof(frame_key));
        sodium_memzero(peer_key, sizeof(peer_key));
        sodium_memzero(eph_priv, sizeof(eph_priv));
        sodium_memzero(peer_priv, sizeof(peer_priv));
        sodium_memzero(resp_eph_priv, sizeof(resp_eph_priv));
        fprintf(stderr, "Deserialization failed\n");
        return 1;
    }

    if (packet_decrypt(&recv_pkt, peer_key) != 0) {
        sodium_memzero(frame_key, sizeof(frame_key));
        sodium_memzero(peer_key, sizeof(peer_key));
        sodium_memzero(eph_priv, sizeof(eph_priv));
        sodium_memzero(peer_priv, sizeof(peer_priv));
        sodium_memzero(resp_eph_priv, sizeof(resp_eph_priv));
        fprintf(stderr, "Voice decryption failed\n");
        return 1;
    }

    printf("Decrypted voice frame: %zu bytes (payload[0]=0x%02X)\n",
           recv_pkt.payload_len, recv_pkt.payload[0]);

    /* Cleanup */
    sodium_memzero(frame_key, sizeof(frame_key));
    sodium_memzero(peer_key, sizeof(peer_key));
    sodium_memzero(eph_priv, sizeof(eph_priv));
    sodium_memzero(peer_priv, sizeof(peer_priv));
    sodium_memzero(resp_eph_priv, sizeof(resp_eph_priv));

    printf("Voice chat demo completed successfully.\n");
    return 0;
}
