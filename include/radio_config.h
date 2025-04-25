#ifndef RADIO_CONFIG_H
#define RADIO_CONFIG_H

#include <stdint.h>

/**
 * @file radio_config.h
 * @brief Configuration parameters for the multiband radio system
 */

/* Band definitions */
#define BAND_433MHZ 0
#define BAND_868MHZ 1
#define BAND_915MHZ 2

/* Regulatory regions */
#define REGION_AMERICAS 0    /* US, Canada, etc. with 915 MHz */
#define REGION_EUROPE   1    /* Europe with 868 MHz */
#define REGION_ASIA     2    /* Parts of Asia */
#define REGION_GLOBAL   3    /* Global with restrictions */

/* Terrain types for band optimization */
#define TERRAIN_URBAN      0
#define TERRAIN_OPEN_FIELD 1
#define TERRAIN_FOREST     2
#define TERRAIN_MIXED      3

/* LoRa configuration parameters */
typedef struct {
    uint32_t frequency;     /* Base frequency in Hz */
    uint8_t  bandwidth;     /* Bandwidth in kHz (125, 250, 500) */
    uint8_t  spreadFactor;  /* Spreading factor (7-12) */
    uint8_t  codingRate;    /* Coding rate (5-8, representing 4/5 to 4/8) */
    uint8_t  txPower;       /* Transmit power in dBm */
    uint8_t  preambleLength;/* Length of preamble */
    uint8_t  band;          /* Which band this config is for */
} radio_config_t;

/* Default configurations for each band */
extern const radio_config_t BAND_CONFIG_433MHZ;
extern const radio_config_t BAND_CONFIG_868MHZ;
extern const radio_config_t BAND_CONFIG_915MHZ;

/* Region-specific configurations */
extern const uint8_t ALLOWED_BANDS_BY_REGION[4][3];  /* [region][band] -> allowed (1/0) */
extern const uint8_t MAX_POWER_BY_REGION_BAND[4][3]; /* [region][band] -> max power in dBm */

/* Terrain optimization presets */
extern const radio_config_t TERRAIN_PRESETS[4][3];   /* [terrain][band] -> radio config */

/**
 * Initializes the radio configuration system
 * 
 * @param region Regulatory region to use
 * @param terrain Terrain type for optimization
 * @return 0 on success, negative on error
 */
int radio_config_init(uint8_t region, uint8_t terrain);

/**
 * Gets the optimal radio configuration based on current conditions
 * 
 * @param config Pointer to radio_config_t structure to fill
 * @return 0 on success, negative on error
 */
int radio_config_get_optimal(radio_config_t* config);

/**
 * Updates environment factors for band selection algorithm
 * 
 * @param noise_floor Array of noise floor measurements for each band
 * @param battery_level Battery level percentage (0-100)
 * @param link_quality Link quality metric (0-100)
 * @return 0 on success, negative on error
 */
int radio_config_update_environment(
    int8_t noise_floor[3], 
    uint8_t battery_level,
    uint8_t link_quality);

#endif /* RADIO_CONFIG_H */