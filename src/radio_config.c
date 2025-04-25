#include "radio_config.h"
#include <string.h>

/* Default configurations for each band */
const radio_config_t BAND_CONFIG_433MHZ = {
    .frequency = 433000000,
    .bandwidth = 125,
    .spreadFactor = 9,
    .codingRate = 5, /* 4/5 coding rate */
    .txPower = 17,   /* Default power in dBm */
    .preambleLength = 8,
    .band = BAND_433MHZ};

const radio_config_t BAND_CONFIG_868MHZ = {
    .frequency = 868000000,
    .bandwidth = 125,
    .spreadFactor = 9,
    .codingRate = 5, /* 4/5 coding rate */
    .txPower = 14,   /* Default power in dBm */
    .preambleLength = 8,
    .band = BAND_868MHZ};

const radio_config_t BAND_CONFIG_915MHZ = {
    .frequency = 915000000,
    .bandwidth = 125,
    .spreadFactor = 9,
    .codingRate = 5, /* 4/5 coding rate */
    .txPower = 17,   /* Default power in dBm */
    .preambleLength = 8,
    .band = BAND_915MHZ};

/* Region-specific band allowances (1 = allowed, 0 = not allowed) */
const uint8_t ALLOWED_BANDS_BY_REGION[4][3] = {
    /* 433MHz, 868MHz, 915MHz */
    {1, 0, 1}, /* REGION_AMERICAS */
    {1, 1, 0}, /* REGION_EUROPE */
    {1, 0, 0}, /* REGION_ASIA */
    {1, 1, 1}  /* REGION_GLOBAL - with restrictions */
};

/* Maximum power by region and band (in dBm) */
const uint8_t MAX_POWER_BY_REGION_BAND[4][3] = {
    /*  433MHz, 868MHz, 915MHz */
    {10, 0, 30}, /* REGION_AMERICAS */
    {10, 14, 0}, /* REGION_EUROPE */
    {10, 0, 0},  /* REGION_ASIA */
    {10, 14, 20} /* REGION_GLOBAL - minimum of all regions */
};

/* Terrain optimization presets */
const radio_config_t TERRAIN_PRESETS[4][3] = {
    /* Urban environment */
    {
        /* 433MHz */
        {
            .frequency = 433000000,
            .bandwidth = 125,
            .spreadFactor = 8,
            .codingRate = 5,
            .txPower = 12,
            .preambleLength = 8,
            .band = BAND_433MHZ},
        /* 868MHz */
        {
            .frequency = 868000000,
            .bandwidth = 125,
            .spreadFactor = 8,
            .codingRate = 5,
            .txPower = 12,
            .preambleLength = 8,
            .band = BAND_868MHZ},
        /* 915MHz */
        {
            .frequency = 915000000,
            .bandwidth = 125,
            .spreadFactor = 8,
            .codingRate = 5,
            .txPower = 12,
            .preambleLength = 8,
            .band = BAND_915MHZ}},
    /* Open field/desert */
    {
        /* 433MHz */
        {
            .frequency = 433000000,
            .bandwidth = 125,
            .spreadFactor = 10,
            .codingRate = 6,
            .txPower = 17,
            .preambleLength = 8,
            .band = BAND_433MHZ},
        /* 868MHz */
        {
            .frequency = 868000000,
            .bandwidth = 125,
            .spreadFactor = 9,
            .codingRate = 6,
            .txPower = 14,
            .preambleLength = 8,
            .band = BAND_868MHZ},
        /* 915MHz */
        {
            .frequency = 915000000,
            .bandwidth = 125,
            .spreadFactor = 9,
            .codingRate = 6,
            .txPower = 17,
            .preambleLength = 8,
            .band = BAND_915MHZ}},
    /* Forest/dense vegetation */
    {
        /* 433MHz */
        {
            .frequency = 433000000,
            .bandwidth = 125,
            .spreadFactor = 11,
            .codingRate = 7,
            .txPower = 17,
            .preambleLength = 8,
            .band = BAND_433MHZ},
        /* 868MHz */
        {
            .frequency = 868000000,
            .bandwidth = 125,
            .spreadFactor = 10,
            .codingRate = 6,
            .txPower = 14,
            .preambleLength = 8,
            .band = BAND_868MHZ},
        /* 915MHz */
        {
            .frequency = 915000000,
            .bandwidth = 125,
            .spreadFactor = 10,
            .codingRate = 6,
            .txPower = 17,
            .preambleLength = 8,
            .band = BAND_915MHZ}},
    /* Mixed terrain */
    {
        /* 433MHz */
        {
            .frequency = 433000000,
            .bandwidth = 125,
            .spreadFactor = 9,
            .codingRate = 6,
            .txPower = 15,
            .preambleLength = 8,
            .band = BAND_433MHZ},
        /* 868MHz */
        {
            .frequency = 868000000,
            .bandwidth = 125,
            .spreadFactor = 9,
            .codingRate = 6,
            .txPower = 12,
            .preambleLength = 8,
            .band = BAND_868MHZ},
        /* 915MHz */
        {
            .frequency = 915000000,
            .bandwidth = 125,
            .spreadFactor = 9,
            .codingRate = 6,
            .txPower = 15,
            .preambleLength = 8,
            .band = BAND_915MHZ}}};

/* Module state */
static struct
{
    uint8_t region;
    uint8_t terrain;
    int8_t noise_floor[3];
    uint8_t battery_level;
    uint8_t link_quality;
    uint8_t current_band;
} radio_state;

/**
 * Initializes the radio configuration system
 */
int radio_config_init(uint8_t region, uint8_t terrain)
{
    /* Validate parameters */
    if (region > REGION_GLOBAL || terrain > TERRAIN_MIXED)
    {
        return -1;
    }

    /* Initialize state */
    radio_state.region = region;
    radio_state.terrain = terrain;
    radio_state.battery_level = 100;
    radio_state.link_quality = 0;
    radio_state.current_band = BAND_433MHZ; /* Default to 433 MHz which is universally allowed */

    /* Set default noise floor values (very low, will be updated by measurements) */
    memset(radio_state.noise_floor, -120, sizeof(radio_state.noise_floor));

    return 0;
}

/**
 * Gets the optimal radio configuration based on current conditions
 */
int radio_config_get_optimal(radio_config_t *config)
{
    if (!config)
    {
        return -1;
    }

    /* Calculate scores for each band */
    int scores[3] = {0};

    /* Check if each band is allowed in this region */
    for (int band = 0; band < 3; band++)
    {
        if (!ALLOWED_BANDS_BY_REGION[radio_state.region][band])
        {
            scores[band] = -1000; /* Not allowed, give a very low score */
            continue;
        }

        /* Base score from terrain preset */
        scores[band] = 0;

        /* Adjust score based on noise floor (lower noise = higher score) */
        scores[band] += ((-120 - radio_state.noise_floor[band]) / 2);

        /* Adjust for battery level (higher SF and power use more battery) */
        if (radio_state.battery_level < 20)
        {
            /* Penalize higher bands and higher SF when battery is low */
            scores[band] -= band * 5;
            if (TERRAIN_PRESETS[radio_state.terrain][band].spreadFactor > 9)
            {
                scores[band] -= 10;
            }
        }

        /* Preferred bands for each terrain type */
        switch (radio_state.terrain)
        {
        case TERRAIN_URBAN:
            /* Prefer 868/915 MHz for urban due to better building penetration */
            if (band == BAND_868MHZ || band == BAND_915MHZ)
            {
                scores[band] += 20;
            }
            break;

        case TERRAIN_OPEN_FIELD:
        case TERRAIN_FOREST:
            /* Prefer 433 MHz for maximum range in open field or forest */
            if (band == BAND_433MHZ)
            {
                scores[band] += 30;
            }
            break;

        case TERRAIN_MIXED:
            /* No strong preference for mixed terrain */
            break;
        }

        /* Consider link quality on the current band */
        if (band == radio_state.current_band && radio_state.link_quality > 50)
        {
            /* Favor the current band if link quality is good (avoid unnecessary switching) */
            scores[band] += 15;
        }
    }

    /* Find the band with the highest score */
    int best_band = 0;
    for (int band = 1; band < 3; band++)
    {
        if (scores[band] > scores[best_band])
        {
            best_band = band;
        }
    }

    /* If the best band score is still negative, it means no band is allowed */
    if (scores[best_band] < 0)
    {
        return -2;
    }

    /* Set the configuration based on the best band and terrain preset */
    radio_config_t base_config = TERRAIN_PRESETS[radio_state.terrain][best_band];

    /* Apply region-specific power limits */
    if (base_config.txPower > MAX_POWER_BY_REGION_BAND[radio_state.region][best_band])
    {
        base_config.txPower = MAX_POWER_BY_REGION_BAND[radio_state.region][best_band];
    }

    /* Copy the result */
    memcpy(config, &base_config, sizeof(radio_config_t));

    /* Update current band */
    radio_state.current_band = best_band;

    return 0;
}

/**
 * Updates environment factors for band selection algorithm
 */
int radio_config_update_environment(
    int8_t noise_floor[3],
    uint8_t battery_level,
    uint8_t link_quality)
{
    /* Update noise floor measurements if provided */
    if (noise_floor)
    {
        memcpy(radio_state.noise_floor, noise_floor, sizeof(radio_state.noise_floor));
    }

    /* Update battery level */
    radio_state.battery_level = battery_level;

    /* Update link quality */
    radio_state.link_quality = link_quality;

    return 0;
}