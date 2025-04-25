#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "security.h"
#include "platform.h"

/* Test cases */
static int test_init(void);
static int test_key_generation(void);
static int test_ecdh(void);
static int test_key_derivation(void);
static int test_encryption_decryption(void);
static int test_nonce_generation(void);
static int test_counter_integrity(void);

int main(void) {
    printf("Testing Security Module\n");
    
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
    
    printf("Test 2: Key generation... ");
    if (test_key_generation() == 0) {
        printf("PASSED\n");
    } else {
        printf("FAILED\n");
        failed++;
    }
    
    printf("Test 3: ECDH... ");
    if (test_ecdh() == 0) {
        printf("PASSED\n");
    } else {
        printf("FAILED\n");
        failed++;
    }
    
    printf("Test 4: Key derivation... ");
    if (test_key_derivation() == 0) {
        printf("PASSED\n");
    } else {
        printf("FAILED\n");
        failed++;
    }
    
    printf("Test 5: Encryption/decryption... ");
    if (test_encryption_decryption() == 0) {
        printf("PASSED\n");
    } else {
        printf("FAILED\n");
        failed++;
    }
    
    printf("Test 6: Nonce generation... ");
    if (test_nonce_generation() == 0) {
        printf("PASSED\n");
    } else {
        printf("FAILED\n");
        failed++;
    }
    
    printf("Test 7: Counter integrity... ");
    if (test_counter_integrity() == 0) {
        printf("PASSED\n");
    } else {
        printf("FAILED\n");
        failed++;
    }
    
    printf("\nTest summary: %d tests, %d passed, %d failed\n", 7, 7 - failed, failed);
    
    return failed ? 1 : 0;
}

/* Test initialization */
static int test_init(void) {
    /* Test valid parameters */
    if (security_init(SECURITY_E2E, CIPHER_AES_GCM) != 0) {
        return -1;
    }
    
    /* Test invalid security mode */
    if (security_init(3, CIPHER_AES_GCM) == 0) {
        return -2;
    }
    
    /* Test invalid cipher */
    if (security_init(SECURITY_E2E, 2) == 0) {
        return -3;
    }
    
    return 0;
}

/* Test key generation */
static int test_key_generation(void) {
    uint8_t public_key[PUBLIC_KEY_LENGTH];
    uint8_t private_key[PRIVATE_KEY_LENGTH];
    
    /* Initialize security */
    if (security_init(SECURITY_E2E, CIPHER_AES_GCM) != 0) {
        return -1;
    }
    
    /* Generate identity key */
    if (security_generate_keypair(KEY_TYPE_IDENTITY, public_key, private_key) != 0) {
        return -2;
    }
    
    /* Verify keys are non-zero */
    int all_zero = 1;
    for (int i = 0; i < PUBLIC_KEY_LENGTH; i++) {
        if (public_key[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    
    if (all_zero) {
        return -3;
    }
    
    all_zero = 1;
    for (int i = 0; i < PRIVATE_KEY_LENGTH; i++) {
        if (private_key[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    
    if (all_zero) {
        return -4;
    }
    
    /* Generate ephemeral key */
    uint8_t public_key2[PUBLIC_KEY_LENGTH];
    uint8_t private_key2[PRIVATE_KEY_LENGTH];
    
    if (security_generate_keypair(KEY_TYPE_EPHEMERAL, public_key2, private_key2) != 0) {
        return -5;
    }
    
    /* Keys should be different */
    if (memcmp(public_key, public_key2, PUBLIC_KEY_LENGTH) == 0) {
        return -6;
    }
    
    if (memcmp(private_key, private_key2, PRIVATE_KEY_LENGTH) == 0) {
        return -7;
    }
    
    return 0;
}

/* Test ECDH */
static int test_ecdh(void) {
    uint8_t alice_public[PUBLIC_KEY_LENGTH];
    uint8_t alice_private[PRIVATE_KEY_LENGTH];
    uint8_t bob_public[PUBLIC_KEY_LENGTH];
    uint8_t bob_private[PRIVATE_KEY_LENGTH];
    uint8_t alice_secret[SHARED_SECRET_LENGTH];
    uint8_t bob_secret[SHARED_SECRET_LENGTH];
    
    /* Initialize security */
    if (security_init(SECURITY_E2E, CIPHER_AES_GCM) != 0) {
        return -1;
    }
    
    /* Generate key pairs */
    if (security_generate_keypair(KEY_TYPE_EPHEMERAL, alice_public, alice_private) != 0) {
        return -2;
    }
    
    if (security_generate_keypair(KEY_TYPE_EPHEMERAL, bob_public, bob_private) != 0) {
        return -3;
    }
    
    /* Compute shared secrets */
    if (security_compute_shared_secret(bob_public, alice_private, alice_secret) != 0) {
        return -4;
    }
    
    if (security_compute_shared_secret(alice_public, bob_private, bob_secret) != 0) {
        return -5;
    }
    
    /* Verify shared secrets match */
    if (memcmp(alice_secret, bob_secret, SHARED_SECRET_LENGTH) != 0) {
        return -6;
    }
    
    return 0;
}

/* Test key derivation */
static int test_key_derivation(void) {
    uint8_t shared_secret[SHARED_SECRET_LENGTH];
    uint8_t tx_key[SYMMETRIC_KEY_LENGTH];
    uint8_t rx_key[SYMMETRIC_KEY_LENGTH];
    
    /* Initialize security */
    if (security_init(SECURITY_E2E, CIPHER_AES_GCM) != 0) {
        return -1;
    }
    
    /* Generate a random shared secret */
    platform_random_bytes(shared_secret, SHARED_SECRET_LENGTH);
    
    /* Derive keys */
    if (security_derive_keys(shared_secret, tx_key, rx_key) != 0) {
        return -2;
    }
    
    /* Verify keys are different */
    if (memcmp(tx_key, rx_key, SYMMETRIC_KEY_LENGTH) == 0) {
        return -3;
    }
    
    /* Verify keys are non-zero */
    int all_zero = 1;
    for (int i = 0; i < SYMMETRIC_KEY_LENGTH; i++) {
        if (tx_key[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    
    if (all_zero) {
        return -4;
    }
    
    all_zero = 1;
    for (int i = 0; i < SYMMETRIC_KEY_LENGTH; i++) {
        if (rx_key[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    
    if (all_zero) {
        return -5;
    }
    
    return 0;
}

/* Test encryption/decryption */
static int test_encryption_decryption(void) {
    uint8_t key[SYMMETRIC_KEY_LENGTH];
    secure_nonce_t nonce;
    uint8_t plaintext[100] = "This is a test message for encryption and decryption.";
    size_t plaintext_len = strlen((char*)plaintext);
    uint8_t ciphertext[100];
    uint8_t tag[TAG_LENGTH];
    uint8_t decrypted[100];
    
    /* Initialize security */
    if (security_init(SECURITY_E2E, CIPHER_AES_GCM) != 0) {
        return -1;
    }
    
    /* Generate a random key */
    platform_random_bytes(key, SYMMETRIC_KEY_LENGTH);
    
    /* Create a nonce */
    memset(&nonce, 0, sizeof(secure_nonce_t));
    platform_random_bytes(nonce.node_id, sizeof(nonce.node_id));
    nonce.counter = 1;
    nonce.random = 0x42;
    
    /* Encrypt */
    if (security_encrypt(key, &nonce, plaintext, plaintext_len, NULL, 0, ciphertext, tag) != 0) {
        return -2;
    }
    
    /* Decrypt */
    if (security_decrypt(key, &nonce, ciphertext, plaintext_len, NULL, 0, tag, decrypted) != 0) {
        return -3;
    }
    
    /* Verify decrypted == plaintext */
    if (memcmp(plaintext, decrypted, plaintext_len) != 0) {
        return -4;
    }
    
    /* Test with AAD */
    const uint8_t aad[] = "Associated data";
    size_t aad_len = strlen((char*)aad);
    
    /* Encrypt with AAD */
    if (security_encrypt(key, &nonce, plaintext, plaintext_len, aad, aad_len, ciphertext, tag) != 0) {
        return -5;
    }
    
    /* Decrypt with AAD */
    if (security_decrypt(key, &nonce, ciphertext, plaintext_len, aad, aad_len, tag, decrypted) != 0) {
        return -6;
    }
    
    /* Verify decrypted == plaintext */
    if (memcmp(plaintext, decrypted, plaintext_len) != 0) {
        return -7;
    }
    
    /* Test with wrong AAD */
    const uint8_t wrong_aad[] = "Wrong data";
    size_t wrong_aad_len = strlen((char*)wrong_aad);
    
    /* Should fail to decrypt with wrong AAD */
    if (security_decrypt(key, &nonce, ciphertext, plaintext_len, wrong_aad, wrong_aad_len, tag, decrypted) == 0) {
        return -8;
    }
    
    /* Test with wrong tag */
    uint8_t wrong_tag[TAG_LENGTH];
    memcpy(wrong_tag, tag, TAG_LENGTH);
    wrong_tag[0] ^= 0x01; /* Flip a bit */
    
    /* Should fail to decrypt with wrong tag */
    if (security_decrypt(key, &nonce, ciphertext, plaintext_len, aad, aad_len, wrong_tag, decrypted) == 0) {
        return -9;
    }
    
    return 0;
}

/* Test nonce generation */
static int test_nonce_generation(void) {
    secure_nonce_t nonce1, nonce2;
    
    /* Initialize security */
    if (security_init(SECURITY_E2E, CIPHER_AES_GCM) != 0) {
        return -1;
    }
    
    /* Get first nonce */
    if (security_get_next_nonce(&nonce1) != 0) {
        return -2;
    }
    
    /* Get second nonce */
    if (security_get_next_nonce(&nonce2) != 0) {
        return -3;
    }
    
    /* Verify counter incremented */
    if (nonce2.counter != nonce1.counter + 1) {
        return -4;
    }
    
    /* Generate several nonces and verify counter keeps incrementing */
    uint64_t last_counter = nonce2.counter;
    for (int i = 0; i < 10; i++) {
        if (security_get_next_nonce(&nonce1) != 0) {
            return -5;
        }
        
        if (nonce1.counter != last_counter + 1) {
            return -6;
        }
        
        last_counter = nonce1.counter;
    }
    
    return 0;
}

/* Test counter integrity */
static int test_counter_integrity(void) {
    /* Initialize security */
    if (security_init(SECURITY_E2E, CIPHER_AES_GCM) != 0) {
        return -1;
    }
    
    /* Verify counter integrity */
    if (security_verify_counter_integrity() != 0) {
        return -2;
    }
    
    /* Generate a nonce to increment the counter */
    secure_nonce_t nonce;
    if (security_get_next_nonce(&nonce) != 0) {
        return -3;
    }
    
    /* Verify counter integrity again */
    if (security_verify_counter_integrity() != 0) {
        return -4;
    }
    
    return 0;
}