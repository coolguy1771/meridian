#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "radio_config.h"

/* Test cases */
static int test_init(void);
static int test_optimal_config(void);
static int test_region_restrictions(void);
static int test_terrain_presets(void);
static int test_environment_updates(void);

int main(void) {
    printf("Testing Radio Configuration Module\n");
    
    int failed = 0;
    
    printf("Test 1: Initialization... ");
    if (test_init() == 0) {
        printf("PASSED\n");
    } else {
        printf("FAILED\n");
        failed++;
    }
    
    printf("Test 2: Optimal configuration... ");
    if (test_optimal_config() == 0) {
        printf("PASSED\n");
    } else {
        printf("FAILED\n");
        failed++;
    }
    
    printf("Test 3: Region restrictions... ");
    if (test_region_restrictions() == 0) {
        printf("PASSED\n");
    } else {
        printf("FAILED\n");
        failed++;
    }
    
    printf("Test 4: Terrain presets... ");
    if (test_terrain_presets() == 0) {
        printf("PASSED\n");
    } else {
        printf("FAILED\n");
        failed++;
    }
    
    printf("Test 5: Environment updates... ");
    if (test_environment_updates() == 0) {
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
    /* Test valid parameters */
    if (radio_config_init(REGION_AMERICAS, TERRAIN_MIXED) != 0) {
        return -1;
    }
    
    /* Test invalid region */
    if (radio_config_init(4, TERRAIN_MIXED) == 0) {
        return -2;
    }
    
    /* Test invalid terrain */
    if (radio_config_init(REGION_AMERICAS, 4) == 0) {
        return -3;
    }
    
    return 0;
}

/* Test getting optimal configuration */
static int test_optimal_config(void) {
    radio_config_t config;
    
    radio_config_init(REGION_AMERICAS, TERRAIN_MIXED);
    
    if (radio_config_get_optimal(&config) != 0) {
        return -1;
    }
    
    /* Check that config has reasonable values */
    if (config.frequency < 400000000 || config.frequency > 950000000) {
        return -2;
    }
    
    if (config.spreadFactor < 7 || config.spreadFactor > 12) {
        return -3;
    }
    
    if (config.bandwidth != 125 && config.bandwidth != 250 && config.bandwidth != 500) {
        return -4;
    }
    
    return 0;
}

/* Test region restrictions */
static int test_region_restrictions(void) {
    radio_config_t config;
    
    /* Test Europe region - should not allow 915 MHz */
    radio_config_init(REGION_EUROPE, TERRAIN_MIXED);
    if (radio_config_get_optimal(&config) != 0) {
        return -1;
    }
    
    /* Config should NOT have 915 MHz frequency */
    if (config.frequency > 900000000) {
        return -2;
    }
    
    /* Test Americas region - should allow 915 MHz */
    radio_config_init(REGION_AMERICAS, TERRAIN_MIXED);
    
    /* Set environmental factors to prefer 915 MHz */
    int8_t noise_floor[3] = {-80, -90, -100}; /* Lowest noise on 915 MHz */
    radio_config_update_environment(noise_floor, 100, 0);
    
    if (radio_config_get_optimal(&config) != 0) {
        return -3;
    }
    
    /* In Americas with low noise on 915 MHz, should prefer it */
    if (config.frequency < 900000000) {
        return -4;
    }
    
    return 0;
}

/* Test terrain presets */
static int test_terrain_presets(void) {
    radio_config_t config;
    
    /* Test urban terrain - should prefer higher frequencies */
    radio_config_init(REGION_GLOBAL, TERRAIN_URBAN);
    if (radio_config_get_optimal(&config) != 0) {
        return -1;
    }
    
    /* Test open field - should prefer 433 MHz */
    radio_config_init(REGION_GLOBAL, TERRAIN_OPEN_FIELD);
    
    /* Reset environmental factors */
    int8_t noise_floor[3] = {-90, -90, -90}; /* Equal noise on all bands */
    radio_config_update_environment(noise_floor, 100, 0);
    
    if (radio_config_get_optimal(&config) != 0) {
        return -2;
    }
    
    /* In open field, should prefer 433 MHz */
    if (config.frequency > 450000000) {
        return -3;
    }
    
    /* Test forest - should have higher spreading factor */
    radio_config_init(REGION_GLOBAL, TERRAIN_FOREST);
    if (radio_config_get_optimal(&config) != 0) {
        return -4;
    }
    
    /* In forest, spreading factor should be higher */
    if (config.spreadFactor < 10) {
        return -5;
    }
    
    return 0;
}

/* Test environment updates */
static int test_environment_updates(void) {
    radio_config_t config1, config2;
    
    radio_config_init(REGION_GLOBAL, TERRAIN_MIXED);
    
    /* Get initial config with default environment */
    if (radio_config_get_optimal(&config1) != 0) {
        return -1;
    }
    
    /* Update environment to strongly prefer 433 MHz */
    int8_t noise_floor[3] = {-120, -80, -80}; /* Much lower noise on 433 MHz */
    radio_config_update_environment(noise_floor, 100, 0);
    
    /* Get updated config */
    if (radio_config_get_optimal(&config2) != 0) {
        return -2;
    }
    
    /* Should now prefer 433 MHz */
    if (config2.frequency > 450000000) {
        return -3;
    }
    
    /* Test low battery scenario */
    radio_config_update_environment(NULL, 10, 0); /* 10% battery */
    
    /* Get updated config */
    if (radio_config_get_optimal(&config2) != 0) {
        return -4;
    }
    
    /* With low battery, should reduce TX power */
    if (config2.txPower > 12) {
        return -5;
    }
    
    return 0;
}