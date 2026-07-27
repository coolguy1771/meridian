#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include "security.h"
#include "packet.h"   /* For MAX_PAYLOAD_SIZE */
#include "platform.h"

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "[FAIL] %s at line %d\n", msg, __LINE__); return -1; } \
} while(0)

static int test_init(void) {
    printf("Testing security init...");
    if (platform_init() != 0) {
        fprintf(stderr, "[FAIL] platform_init failed\n");
        return -1;
    }

    if (security_init(SECURITY_E2E, CIPHER_XCHACHA20_POLY) != 0) {
        fprintf(stderr, "[FAIL] security_init failed\n");
        return -1;
    }
    printf("[PASS]\n");
    return 0;
}

static int test_key_generation(void) {
    printf("Testing key generation...");

    uint8_t pub[PUBLIC_KEY_LENGTH], priv[PRIVATE_KEY_LENGTH];

    if (crypto_box_keypair(pub, priv) != 0) {
        fprintf(stderr, "[FAIL] crypto_box_keypair\n");
        return -1;
    }

    /* Ensure key lengths are reasonable */
    TEST_ASSERT(sodium_memcmp(pub, "\x00\x00\x00\x00\x00\x00\x00\x00", 8) != 0, "Public key looks zeroed");

    printf("[PASS]\n");
    return 0;
}

static int test_ecdh(void) {
    printf("Testing ECDH key exchange...");

    if (platform_init() != 0 || security_init(SECURITY_E2E, CIPHER_XCHACHA20_POLY) != 0) {
        fprintf(stderr, "[FAIL] init for ecdh test\n");
        return -1;
    }

    /* Alice & Bob each have identity keys via the subsystem */
    uint8_t alice_pub[PUBLIC_KEY_LENGTH], alice_priv[PRIVATE_KEY_LENGTH];
    uint8_t bob_pub[PUBLIC_KEY_LENGTH], bob_priv[PRIVATE_KEY_LENGTH];

    crypto_box_keypair(alice_pub, alice_priv);
    crypto_box_keypair(bob_pub, bob_priv);

    /* Temporarily set subsystem identity keys to test compute_shared_secret */
    if (security_store_identity_keys(alice_pub, alice_priv) != 0) {
        fprintf(stderr, "[FAIL] store alice keys\n");
        return -1;
    }

    uint8_t alice_shared[SHARED_SECRET_LENGTH];
    TEST_ASSERT(security_compute_shared_secret(bob_pub, alice_shared) == 0, "alice DH failed");

    /* Now Bob perspective */
    if (security_store_identity_keys(bob_pub, bob_priv) != 0) {
        fprintf(stderr, "[FAIL] store bob keys\n");
        return -1;
    }

    uint8_t bob_shared[SHARED_SECRET_LENGTH];
    TEST_ASSERT(security_compute_shared_secret(alice_pub, bob_shared) == 0, "bob DH failed");

    TEST_ASSERT(sodium_memcmp(alice_shared, bob_shared, SHARED_SECRET_LENGTH) == 0,
                "shared secrets mismatch");

    sodium_memzero(alice_priv, sizeof(alice_priv));
    sodium_memzero(bob_priv, sizeof(bob_priv));
    sodium_memzero(alice_shared, sizeof(alice_shared));
    sodium_memzero(bob_shared, sizeof(bob_shared));

    printf("[PASS]\n");
    return 0;
}

static int test_key_derivation(void) {
    printf("Testing session key derivation...");

    uint8_t shared[SHARED_SECRET_LENGTH];
    randombytes_buf(shared, SHARED_SECRET_LENGTH);

    uint8_t sess1[SYMMETRIC_KEY_LENGTH], sess2[SYMMETRIC_KEY_LENGTH];

    TEST_ASSERT(security_derive_session_key(shared, 0x0001, 0x0002, sess1) == 0, "derive1 fail");
    TEST_ASSERT(security_derive_session_key(shared, 0x0001, 0x0002, sess2) == 0, "derive2 fail");

    TEST_ASSERT(sodium_memcmp(sess1, sess2, SYMMETRIC_KEY_LENGTH) == 0, "derived keys mismatch");

    uint8_t sess_diff[SYMMETRIC_KEY_LENGTH];
    TEST_ASSERT(security_derive_session_key(shared, 0x0001, 0x00FF, sess_diff) == 0, "derive diff fail");
    TEST_ASSERT(sodium_memcmp(sess1, sess_diff, SYMMETRIC_KEY_LENGTH) != 0, "should differ for different peer_id");

    sodium_memzero(shared, sizeof(shared));
    printf("[PASS]\n");
    return 0;
}

static int test_encryption_decryption(void) {
    printf("Testing encrypt/decrypt roundtrip...");

    if (platform_init() != 0 || security_init(SECURITY_E2E_AUTH, CIPHER_XCHACHA20_POLY) != 0) {
        fprintf(stderr, "[FAIL] init for enc test\n");
        return -1;
    }

    uint8_t key[SYMMETRIC_KEY_LENGTH];
    randombytes_buf(key, SYMMETRIC_KEY_LENGTH);

    const char *plaintext = "Hello Meridian mesh network!";
    size_t len = strlen(plaintext);

    secure_nonce_t nonce;
    TEST_ASSERT(security_get_next_nonce(&nonce) == 0, "nonce fail");

    uint8_t ct[MAX_PAYLOAD_SIZE];
    uint8_t tag[TAG_LENGTH];
    uint8_t aad[16] = "AAD_HEADER";

    int rc = security_encrypt(key, &nonce, (uint8_t*)plaintext, len,
                              aad, sizeof(aad), ct, tag);
    TEST_ASSERT(rc > 0, "encrypt failed");

    uint8_t pt[MAX_PAYLOAD_SIZE];
    rc = security_decrypt(key, &nonce, ct, len,
                          aad, sizeof(aad), tag, pt);
    TEST_ASSERT(rc > 0, "decrypt failed");
    TEST_ASSERT(memcmp(plaintext, pt, len) == 0, "roundtrip mismatch");

    /* Tamper with ciphertext -> should fail auth */
    ct[3] ^= 0xFF;
    rc = security_decrypt(key, &nonce, ct, len,
                          aad, sizeof(aad), tag, pt);
    TEST_ASSERT(rc < 0, "tampered packet accepted");

    /* Tamper with AAD -> should fail auth */
    const char *plaintext2 = "Second message";
    size_t len2 = strlen(plaintext2);

    uint8_t ct2[MAX_PAYLOAD_SIZE], tag2[TAG_LENGTH];
    security_get_next_nonce(&nonce);
    TEST_ASSERT(security_encrypt(key, &nonce, (uint8_t*)plaintext2, len2,
                                 aad, sizeof(aad), ct2, tag2) > 0, "encrypt2 fail");

    uint8_t bad_aad[16] = {0};
    rc = security_decrypt(key, &nonce, ct2, len2,
                          bad_aad, sizeof(bad_aad), tag2, pt);
    TEST_ASSERT(rc < 0, "AAD tamper accepted");

    sodium_memzero(key, sizeof(key));
    printf("[PASS]\n");
    return 0;
}

static int test_nonce_generation(void) {
    printf("Testing nonce uniqueness...");

    if (platform_init() != 0 || security_init(SECURITY_E2E, CIPHER_XCHACHA20_POLY) != 0) {
        fprintf(stderr, "[FAIL] init for nonce test\n");
        return -1;
    }

    secure_nonce_t n[256];
    for (int i = 0; i < 256; i++) {
        TEST_ASSERT(security_get_next_nonce(&n[i]) == 0, "nonce gen fail");
    }

    /* All nonces must be unique */
    for (int i = 0; i < 256; i++) {
        for (int j = i + 1; j < 256; j++) {
            TEST_ASSERT(n[i].value != n[j].value, "duplicate nonce");
        }
    }

    /* Monotonic part should increase */
    uint64_t mono_shift = NONCE_MONOTONIC_BITS;
    for (int i = 1; i < 256; i++) {
        uint64_t prev_mono = n[i-1].value >> mono_shift;
        uint64_t curr_mono = n[i].value >> mono_shift;
        TEST_ASSERT(curr_mono >= prev_mono, "nonce monotonicity violated");
    }

    printf("[PASS]\n");
    return 0;
}

static int test_session_management(void) {
    printf("Testing session management...");

    if (platform_init() != 0 || security_init(SECURITY_E2E_AUTH, CIPHER_XCHACHA20_POLY) != 0) {
        fprintf(stderr, "[FAIL] init for session test\n");
        return -1;
    }

    uint8_t key1[SYMMETRIC_KEY_LENGTH], key2[SYMMETRIC_KEY_LENGTH];
    randombytes_buf(key1, SYMMETRIC_KEY_LENGTH);
    randombytes_buf(key2, SYMMETRIC_KEY_LENGTH);

    uint16_t peer_a = 0x0100, peer_b = 0x0200;

    TEST_ASSERT(security_set_session(peer_a, key1) == 0, "set session A fail");
    TEST_ASSERT(security_set_session(peer_b, key2) == 0, "set session B fail");

    uint8_t retrieved[SYMMETRIC_KEY_LENGTH];

    TEST_ASSERT(security_get_session_key(peer_a, retrieved) == 0, "get session A fail");
    TEST_ASSERT(sodium_memcmp(key1, retrieved, SYMMETRIC_KEY_LENGTH) == 0, "key A mismatch");

    TEST_ASSERT(security_get_session_key(peer_b, retrieved) == 0, "get session B fail");
    TEST_ASSERT(sodium_memcmp(key2, retrieved, SYMMETRIC_KEY_LENGTH) == 0, "key B mismatch");

    TEST_ASSERT(security_get_session_key(0xFFFF, retrieved) == -1, "unknown peer should fail");

    sodium_memzero(key1, sizeof(key1));
    sodium_memzero(key2, sizeof(key2));

    printf("[PASS]\n");
    return 0;
}

static int test_identity_storage(void) {
    printf("Testing identity key generation + store API...");

    if (platform_init() != 0 || security_init(SECURITY_E2E, CIPHER_XCHACHA20_POLY) != 0) {
        fprintf(stderr, "[FAIL] init for storage test\n");
        return -1;
    }

    uint8_t pub[PUBLIC_KEY_LENGTH], priv[PRIVATE_KEY_LENGTH];
    crypto_box_keypair(pub, priv);

    /* On simulated platform (Linux), flash is stubbed and cannot roundtrip.
     * We verify: store API completes without error and internal state is updated. */
    TEST_ASSERT(security_store_identity_keys(pub, priv) == 0, "store identity fail");

    uint8_t loaded_pub[PUBLIC_KEY_LENGTH], loaded_priv[PRIVATE_KEY_LENGTH];

#ifdef PLATFORM_REAL_FLASH
    /* Real hardware path: verify reload matches */
    if (security_load_identity_keys(loaded_pub, loaded_priv) != 0) {
        fprintf(stderr, "[FAIL] load identity failed on real flash\n");
        return -1;
    }
    TEST_ASSERT(sodium_memcmp(pub, loaded_pub, PUBLIC_KEY_LENGTH) == 0, "pub key mismatch on reload");
    TEST_ASSERT(sodium_memcmp(priv, loaded_priv, PRIVATE_KEY_LENGTH) == 0, "priv key mismatch on reload");

    sodium_memzero(priv, sizeof(priv));
    sodium_memzero(loaded_priv, sizeof(loaded_priv));
#else
    /* Simulated platform: we cannot verify persistence across load() because flash is stubbed.
     * Instead, verify that the in-memory identity keys are set correctly via store(). */
    TEST_ASSERT(security_get_identity_public_key(loaded_pub) == 0, "get_identity_pubkey fail");
    TEST_ASSERT(sodium_memcmp(pub, loaded_pub, PUBLIC_KEY_LENGTH) == 0, "stored pub not reflected in memory");
#endif

    sodium_memzero(priv, sizeof(priv));

    printf("[PASS]\n");
    return 0;
}

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    int failures = 0;

    if (test_init()) failures++;
    if (test_key_generation()) failures++;
    if (test_ecdh()) failures++;
    if (test_key_derivation()) failures++;
    if (test_encryption_decryption()) failures++;
    if (test_nonce_generation()) failures++;
    if (test_session_management()) failures++;
    if (test_identity_storage()) failures++;

    printf("\n%d test(s) run. %d failure(s).\n", 8, failures);
    return failures;
}
