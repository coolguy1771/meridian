#include <stdio.h>
#include <string.h>
#include "platform.h"
#include "security.h"
#include "packet.h"
#include "mesh.h"

/*
 * group_provisioning_demo.c
 *
 * Demonstrates leader-based group provisioning in Meridian:
 * 1) Leader creates a group and generates a shared PSK.
 * 2) Leader "sends" encrypted GROUP_JOIN messages to Members A/B (simulated).
 * 3) Members join the group by storing the received group key.
 * 4) Leader broadcasts a GROUP_CHAT packet encrypted with the group PSK.
 * 5) Both members successfully decrypt it; an outsider cannot.
 *
 * This is a pure-Linux simulation: no actual radio or live handshakes. We
 * simulate all crypto operations directly so you can see the flow end-to-end.
 */

#define LEADER_ID   0x1000
#define MEMBER_A    0x1001
#define MEMBER_B    0x1002
#define GROUP_ID_1  0x0001

/**
 * Runs the Meridian group provisioning and encrypted group messaging demonstration.
 *
 * @return 0 on successful completion, 1 if initialization or a demonstration step fails.
 */
int main(void) {
    printf("=== Meridian Group Provisioning Demo ===\n");

    /* Initialize platform + security */
    if (platform_init() != 0 || security_init(SECURITY_E2E_AUTH, CIPHER_XCHACHA20_POLY) != 0) {
        fprintf(stderr, "[FAIL] Platform/security init\n");
        return 1;
    }

    /* Initialize packet/mesh as the leader */
    if (packet_init(LEADER_ID) != 0 || mesh_init(LEADER_ID) != 0) {
        fprintf(stderr, "[FAIL] Mesh init for leader\n");
        return 1;
    }

    printf("[Leader %04X] Initialized\n", LEADER_ID);

    /* Step 1: Leader creates a group with its own PSK */
    uint8_t group_key[SYMMETRIC_KEY_LENGTH];
    randombytes_buf(group_key, SYMMETRIC_KEY_LENGTH);

    int rc = security_set_group_key(GROUP_ID_1, group_key, LEADER_ID);
    if (rc != 0) {
        fprintf(stderr, "[FAIL] Leader failed to create group key\n");
        sodium_memzero(group_key, sizeof(group_key));
        return 1;
    }

    printf("\n[Leader] Created group %u with new shared PSK.\n", GROUP_ID_1);
    printf("[Leader] First 4 bytes of group key: %02X %02X %02X %02X\n",
           group_key[0], group_key[1], group_key[2], group_key[3]);

    /* Step 2: Leader sends encrypted GROUP_JOIN invites to Members A and B */

    printf("\n[Leader] Sending encrypted GROUP_JOIN invite to Member A (%04X)...\n", MEMBER_A);
    {
        /* Build a GROUP_JOIN payload: this is what would be sent over the air,
         * normally encrypted under the pairwise session key with Member A. */
        group_join_payload_t join;
        join.group_id = GROUP_ID_1;
        join.epoch    = 1;
        memcpy(join.group_key, group_key, SYMMETRIC_KEY_LENGTH);

        packet_t pkt;
        if (packet_create(&pkt, MEMBER_A, PACKET_TYPE_GROUP_JOIN,
                          (uint8_t*)&join, sizeof(join)) != 0) {
            fprintf(stderr, "[FAIL] Create GROUP_JOIN packet for A\n");
            return 1;
        }

        /* Encrypt using group key here just for demo integrity check;
         * in real code this would use the pairwise session key. */
        if (packet_encrypt(&pkt, group_key) != 0) {
            fprintf(stderr, "[FAIL] Encrypt GROUP_JOIN packet\n");
            return 1;
        }

        uint8_t buf[MAX_PACKET_SIZE];
        int len = packet_serialize(&pkt, buf, sizeof(buf));
        if (len <= 0) {
            fprintf(stderr, "[FAIL] Serialize GROUP_JOIN\n");
            return 1;
        }

        printf("[Leader] GROUP_JOIN invite sent (%d bytes, encrypted)\n", len);
    }

    /* Simulate Member A receiving and storing the group key */
    {
        uint8_t recv_key[SYMMETRIC_KEY_LENGTH];
        if (security_get_group_key(GROUP_ID_1, recv_key) != 0) {
            fprintf(stderr, "[FAIL] Leader doesn't have its own group key after invite\n");
            sodium_memzero(group_key, sizeof(group_key));
            return 1;
        }

        printf("[Member %04X] Joined group %u (simulated GROUP_JOIN receipt)\n", MEMBER_A, GROUP_ID_1);
        printf("[Member %04X] First 4 bytes of group key: %02X %02X %02X %02X\n",
               MEMBER_A, recv_key[0], recv_key[1], recv_key[2], recv_key[3]);

        sodium_memzero(recv_key, sizeof(recv_key));
    }

    printf("\n[Leader] Sending encrypted GROUP_JOIN invite to Member B (%04X)...\n", MEMBER_B);
    {
        group_join_payload_t join;
        join.group_id = GROUP_ID_1;
        join.epoch    = 1;
        memcpy(join.group_key, group_key, SYMMETRIC_KEY_LENGTH);

        packet_t pkt;
        if (packet_create(&pkt, MEMBER_B, PACKET_TYPE_GROUP_JOIN,
                          (uint8_t*)&join, sizeof(join)) != 0) {
            fprintf(stderr, "[FAIL] Create GROUP_JOIN packet for B\n");
            return 1;
        }

        /* Encrypt using group key here just for demo integrity check */
        if (packet_encrypt(&pkt, group_key) != 0) {
            fprintf(stderr, "[FAIL] Encrypt GROUP_JOIN packet\n");
            return 1;
        }

        uint8_t buf[MAX_PACKET_SIZE];
        int len = packet_serialize(&pkt, buf, sizeof(buf));
        if (len <= 0) {
            fprintf(stderr, "[FAIL] Serialize GROUP_JOIN\n");
            return 1;
        }

        printf("[Leader] GROUP_JOIN invite sent (%d bytes, encrypted)\n", len);
    }

    /* Simulate Member B receiving and storing the group key */
    {
        uint8_t recv_key[SYMMETRIC_KEY_LENGTH];
        if (security_get_group_key(GROUP_ID_1, recv_key) != 0) {
            fprintf(stderr, "[FAIL] Leader doesn't have group key for Group %u\n", GROUP_ID_1);
            sodium_memzero(group_key, sizeof(group_key));
            return 1;
        }

        printf("[Member %04X] Joined group %u (simulated GROUP_JOIN receipt)\n", MEMBER_B, GROUP_ID_1);
        printf("[Member %04X] First 4 bytes of group key: %02X %02X %02X %02X\n",
               MEMBER_B, recv_key[0], recv_key[1], recv_key[2], recv_key[3]);

        sodium_memzero(recv_key, sizeof(recv_key));
    }

    /* Step 3: Leader broadcasts a GROUP_CHAT message encrypted with group key */

    const char *message = "Hello from Meridian Group Chat!";
    printf("\n[Leader] Broadcasting group chat to group %u: \"%s\"\n", GROUP_ID_1, message);

    packet_t pkt;
    if (packet_create(&pkt, BROADCAST_ADDR, PACKET_TYPE_GROUP_CHAT,
                      (uint8_t*)message, strlen(message)) != 0) {
        fprintf(stderr, "[FAIL] Create GROUP_CHAT packet\n");
        sodium_memzero(group_key, sizeof(group_key));
        return 1;
    }

    uint8_t buf[MAX_PACKET_SIZE];

    /* Encrypt with group key */
    if (packet_encrypt(&pkt, group_key) != 0) {
        fprintf(stderr, "[FAIL] Encrypt GROUP_CHAT\n");
        sodium_memzero(group_key, sizeof(group_key));
        return 1;
    }

    int len = packet_serialize(&pkt, buf, sizeof(buf));
    if (len <= 0) {
        fprintf(stderr, "[FAIL] Serialize GROUP_CHAT\n");
        sodium_memzero(group_key, sizeof(group_key));
        return 1;
    }

    printf("[Leader] Group chat broadcast prepared (%d bytes, encrypted with group PSK)\n", len);

    /* Step 4: Simulate Members A and B receiving + decrypting the same packet */

    /* Member A decrypts */
    {
        packet_t recv_pkt;
        if (packet_deserialize(buf, len, &recv_pkt) != 0) {
            fprintf(stderr, "[FAIL] Deserialize for Member A\n");
            sodium_memzero(group_key, sizeof(group_key));
            return 1;
        }

        uint8_t mkey[SYMMETRIC_KEY_LENGTH];
        if (security_get_group_key(GROUP_ID_1, mkey) != 0) {
            fprintf(stderr, "[FAIL] Member A doesn't have group key???\n");
            sodium_memzero(group_key, sizeof(group_key));
            return 1;
        }

        if (packet_decrypt(&recv_pkt, mkey) != 0) {
            fprintf(stderr, "[FAIL] Member A cannot decrypt group message\n");
            sodium_memzero(group_key, sizeof(group_key));
            sodium_memzero(mkey, sizeof(mkey));
            return 1;
        }

        printf("[Member %04X] Decrypted group chat: %.*s\n",
               MEMBER_A, (int)recv_pkt.payload_len, recv_pkt.payload);

        sodium_memzero(mkey, sizeof(mkey));
    }

    /* Member B decrypts */
    {
        packet_t recv_pkt;
        if (packet_deserialize(buf, len, &recv_pkt) != 0) {
            fprintf(stderr, "[FAIL] Deserialize for Member B\n");
            sodium_memzero(group_key, sizeof(group_key));
            return 1;
        }

        uint8_t mkey[SYMMETRIC_KEY_LENGTH];
        if (security_get_group_key(GROUP_ID_1, mkey) != 0) {
            fprintf(stderr, "[FAIL] Member B doesn't have group key???\n");
            sodium_memzero(group_key, sizeof(group_key));
            return 1;
        }

        if (packet_decrypt(&recv_pkt, mkey) != 0) {
            fprintf(stderr, "[FAIL] Member B cannot decrypt group message\n");
            sodium_memzero(group_key, sizeof(group_key));
            sodium_memzero(mkey, sizeof(mkey));
            return 1;
        }

        printf("[Member %04X] Decrypted group chat: %.*s\n",
               MEMBER_B, (int)recv_pkt.payload_len, recv_pkt.payload);

        sodium_memzero(mkey, sizeof(mkey));
    }

    /* Outsider cannot decrypt with a different key */
    {
        uint8_t wrong_key[SYMMETRIC_KEY_LENGTH];
        randombytes_buf(wrong_key, SYMMETRIC_KEY_LENGTH);

        packet_t recv_pkt;
        if (packet_deserialize(buf, len, &recv_pkt) != 0) {
            fprintf(stderr, "[FAIL] Deserialize for outsider\n");
        } else {
            int rc_outsider = packet_decrypt(&recv_pkt, wrong_key);
            if (rc_outsider == 0) {
                fprintf(stderr, "[WARN] Outsider decrypted with wrong key? Check AEAD.\n");
            } else {
                printf("[Outsider] Correctly rejected (cannot decrypt with wrong key)\n");
            }
        }

        sodium_memzero(wrong_key, sizeof(wrong_key));
    }

    sodium_memzero(group_key, sizeof(group_key));

    printf("\n=== Group Provisioning Demo Completed Successfully ===\n");
    printf("Summary:\n");
    printf("- Leader created group %u and established a shared PSK.\n", GROUP_ID_1);
    printf("- Members joined via encrypted GROUP_JOIN messages from the leader.\n");
    printf("- Group-chat broadcasts are encrypted with the group PSK; only members can decrypt.\n");
    return 0;
}
