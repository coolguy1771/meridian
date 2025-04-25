#include "rtc.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <math.h>

/* Constants */
#define RTC_STATE_ADDR 0x70000 /* Flash address for storing RTC state */
#define RTC_LOG_ADDR 0x72000   /* Flash address for RTC event log */

/* Minimum valid time (Jan 1, 2020 00:00:00 UTC) */
#define RTC_MIN_VALID_TIME 1577836800

/* Hardware RTC register addresses (for DS3231) */
#define DS3231_REG_SECONDS 0x00
#define DS3231_REG_MINUTES 0x01
#define DS3231_REG_HOURS 0x02
#define DS3231_REG_DAY 0x04
#define DS3231_REG_MONTH 0x05
#define DS3231_REG_YEAR 0x06
#define DS3231_REG_TEMP_MSB 0x11
#define DS3231_REG_TEMP_LSB 0x12
#define DS3231_REG_STATUS 0x0F

/* Module state with enhanced fields */
static struct
{
    rtc_state_enum_t state; /* Current RTC state */
    int initialized;        /* Initialization status */
    int has_backup;         /* Backup power status */
    time_t time_offset;     /* Offset between RTC time and system time */
    float temperature;      /* Current temperature reading */
    time_t last_sync_time;  /* Last time synchronized with trusted source */
    int32_t drift_rate;     /* Measured drift in PPM */
    uint32_t error_count;   /* Number of errors encountered */
    uint8_t auth_token[32]; /* Internal auth token for time changes */
} rtc_state;

/* Internal function prototypes */
static int verify_rtc_auth_token(const uint8_t *token, size_t token_len);
static void generate_internal_auth_token(uint8_t *token, size_t token_len);
static uint32_t calculate_crc32(const void *data, size_t len);
static int ds3231_read_register(uint8_t reg, uint8_t *value);
static int ds3231_write_register(uint8_t reg, uint8_t value);
static float read_backup_battery_voltage(void);

/**
 * Initialize the RTC subsystem
 */
int rtc_init(void)
{
    /* In a real implementation, this would initialize the DS3231 RTC */
    /* For this simulation, we'll just use the system clock */

    /* Initialize state structure */
    memset(&rtc_state, 0, sizeof(rtc_state));
    rtc_state.state = RTC_STATE_UNINITIALIZED;
    rtc_state.temperature = 25.0f; /* Room temperature */

    /* Try to load saved state from persistent storage */
    if (rtc_load_state() == 0)
    {
        /* If state was loaded successfully, we consider RTC already initialized */
        rtc_state.state = RTC_STATE_INITIALIZED;
        rtc_log_event(RTC_EVENT_INIT, "RTC initialized from persistent state", 0);
    }
    else
    {
        /* Generate a new authentication token */
        generate_internal_auth_token(rtc_state.auth_token, sizeof(rtc_state.auth_token));

        /* Check if hardware RTC is available */
        time_t hw_time;
        if (rtc_hw_get_time(&hw_time) == 0)
        {
            /* Use hardware RTC time if it seems valid */
            if (hw_time >= RTC_MIN_VALID_TIME)
            {
                rtc_state.time_offset = hw_time - time(NULL);
                rtc_state.last_sync_time = time(NULL);
                rtc_log_event(RTC_EVENT_INIT, "RTC initialized from hardware clock", 0);
            }
            else
            {
                rtc_state.time_offset = 0;
                rtc_log_event(RTC_EVENT_INIT, "Hardware RTC time invalid, using system time", 0);
            }
        }
        else
        {
            /* No hardware RTC, use system time */
            rtc_state.time_offset = 0;
            rtc_log_event(RTC_EVENT_INIT, "No hardware RTC, using system time", 0);
        }
    }

    /* Check for tampering */
    if (rtc_check_for_tampering() > 0)
    {
        rtc_state.state = RTC_STATE_TAMPERED;
        rtc_log_event(RTC_EVENT_TAMPER, "Tampering detected during initialization", 0);
    }
    else
    {
        /* Set initialized state */
        rtc_state.initialized = 1;
        rtc_state.state = RTC_STATE_INITIALIZED;
    }

    /* Check if RTC has backup power */
    rtc_state.has_backup = rtc_has_backup_power();

    /* Read temperature */
    rtc_state.temperature = rtc_get_temperature();

    /* Save state to persistent storage */
    rtc_save_state();

    return 0;
}

/**
 * Get the current time from the RTC
 */
int rtc_get_time(time_t *t)
{
    if (!rtc_state.initialized || !t)
    {
        return -1;
    }

    /* Get system time and apply offset */
    *t = time(NULL) + rtc_state.time_offset;

    return 0;
}

/**
 * Set the RTC time
 */
int rtc_set_time(time_t new_time)
{
    if (!rtc_state.initialized)
    {
        return -1;
    }

    /* Validate time is within reasonable bounds */
    time_t current_time = time(NULL);
    time_t max_valid_time = current_time + 31536000; /* Current time + 1 year */

    if (new_time < RTC_MIN_VALID_TIME || new_time > max_valid_time)
    {
        rtc_log_event(RTC_EVENT_ERROR, "RTC set time failed - value out of reasonable bounds", (int32_t)new_time);
        rtc_state.error_count++;
        return -2; /* Time out of reasonable bounds */
    }

    /* Calculate the offset from system time */
    rtc_state.time_offset = new_time - current_time;

    /* Update state */
    rtc_state.last_sync_time = current_time;
    rtc_state.state = RTC_STATE_SYNCHRONIZED;

    /* Log the event */
    rtc_log_event(RTC_EVENT_SET_TIME, "RTC time set", (int32_t)new_time);

    /* Save to persistent storage */
    rtc_save_state();

    return 0;
}

/**
 * Set the RTC time with authentication
 */
int rtc_set_time_auth(time_t new_time, const uint8_t *auth_token, size_t token_len)
{
    if (!rtc_state.initialized || !auth_token || token_len == 0)
    {
        return -1;
    }

    /* Verify authentication token */
    if (!verify_rtc_auth_token(auth_token, token_len))
    {
        rtc_log_event(RTC_EVENT_ERROR, "RTC set time failed - authentication failed", 0);
        rtc_state.error_count++;
        return -3; /* Authentication failed */
    }

    /* Validate time is within reasonable bounds */
    time_t current_time = time(NULL);
    time_t max_valid_time = current_time + 31536000; /* Current time + 1 year */

    if (new_time < RTC_MIN_VALID_TIME || new_time > max_valid_time)
    {
        rtc_log_event(RTC_EVENT_ERROR, "RTC set time failed - value out of reasonable bounds", (int32_t)new_time);
        rtc_state.error_count++;
        return -2; /* Time out of reasonable bounds */
    }

    /* Calculate the offset from system time */
    rtc_state.time_offset = new_time - current_time;

    /* Update state */
    rtc_state.last_sync_time = current_time;
    rtc_state.state = RTC_STATE_SYNCHRONIZED;

    /* Log the event */
    rtc_log_event(RTC_EVENT_SET_TIME, "RTC time set with authentication", (int32_t)new_time);

    /* Save to persistent storage */
    rtc_save_state();

    return 0;
}

/**
 * Adjust the RTC time gradually
 */
int rtc_adjust_time(int32_t offset)
{
    if (!rtc_state.initialized)
    {
        return -1;
    }

    /* Track time of last adjustment and total recent adjustments */
    static time_t last_adjustment_time = 0;
    static int32_t recent_adjustments = 0;
    static const int32_t MAX_ADJUSTMENT_WINDOW = 3600;   /* 1 hour */
    static const int32_t MAX_ADJUSTMENT_THRESHOLD = 300; /* 5 minutes (in seconds) */

    time_t current_time = time(NULL);

    /* Reset tracking if window has passed */
    if (last_adjustment_time == 0 || difftime(current_time, last_adjustment_time) > MAX_ADJUSTMENT_WINDOW)
    {
        recent_adjustments = 0;
    }

    /* Check if adjustments exceed threshold */
    int32_t abs_offset = (offset > 0) ? offset : -offset;
    if (recent_adjustments + abs_offset > MAX_ADJUSTMENT_THRESHOLD)
    {
        /* Log suspicious activity */
        rtc_log_event(RTC_EVENT_ERROR, "Suspicious time adjustment detected", offset);
        rtc_state.error_count++;
        rtc_state.state = RTC_STATE_ERROR;
        return -2;
    }

    /* Apply a fraction of the offset to avoid large jumps */
    int32_t adjustment = offset / 4; /* Apply 25% of the requested adjustment */

    if (adjustment == 0)
    {
        /* Ensure we make at least a small adjustment */
        adjustment = (offset > 0) ? 1 : -1;
    }

    rtc_state.time_offset += adjustment;
    recent_adjustments += (adjustment > 0) ? adjustment : -adjustment;
    last_adjustment_time = current_time;

    /* Log the adjustment */
    rtc_log_event(RTC_EVENT_ADJUST_TIME, "RTC time adjusted", adjustment);

    /* Save state periodically (once per hour) */
    if (difftime(current_time, rtc_state.last_sync_time) > 3600)
    {
        rtc_state.last_sync_time = current_time;
        rtc_save_state();
    }

    return 0;
}

/**
 * Calculate time drift between local and peer time
 *
 * This improved implementation uses floating-point arithmetic for better precision
 * and calculates drift rate in parts per million (PPM).
 */
int32_t rtc_calculate_drift(
    time_t peer_time,
    uint64_t peer_counter,
    uint64_t local_counter,
    float avg_message_rate)
{
    if (!rtc_state.initialized || avg_message_rate <= 0)
    {
        return 0;
    }

    /* Calculate expected time difference with floating-point for precision */
    int64_t counter_diff = (int64_t)peer_counter - (int64_t)local_counter;
    double expected_time_diff = (double)counter_diff / avg_message_rate;

    /* Get current local time */
    time_t local_time;
    rtc_get_time(&local_time);

    /* Calculate actual time difference */
    double actual_time_diff = difftime(local_time, peer_time);

    /* Calculate drift */
    double drift = actual_time_diff - expected_time_diff;

    /* Calculate drift rate in parts per million (PPM) */
    if (fabs(expected_time_diff) > 60.0)
    { /* Only calculate if we have enough data */
        /* Drift rate = (drift / expected_time_diff) * 1,000,000 */
        double drift_rate_ppm = (drift / expected_time_diff) * 1000000.0;

        /* Update the drift rate with exponential moving average */
        if (rtc_state.drift_rate == 0)
        {
            rtc_state.drift_rate = (int32_t)drift_rate_ppm;
        }
        else
        {
            rtc_state.drift_rate = (rtc_state.drift_rate * 3 + (int32_t)drift_rate_ppm) / 4;
        }

        /* Log significant drift */
        if (fabs(drift_rate_ppm) > 100.0)
        { /* More than 100 PPM is significant */
            rtc_log_event(RTC_EVENT_ADJUST_TIME, "Significant clock drift detected", (int32_t)drift_rate_ppm);
        }
    }

    /* Return the drift in seconds */
    return (int32_t)drift;
}

/**
 * Check if the RTC has valid time
 */
int rtc_has_valid_time(void)
{
    if (!rtc_state.initialized)
    {
        return 0;
    }

    /* Check if the RTC is in a valid state */
    if (rtc_state.state == RTC_STATE_ERROR || rtc_state.state == RTC_STATE_TAMPERED)
    {
        return 0;
    }

    /* Get current time to verify */
    time_t current_time;
    rtc_get_time(&current_time);

    /* Verify time is reasonable */
    if (current_time < RTC_MIN_VALID_TIME)
    {
        rtc_log_event(RTC_EVENT_ERROR, "RTC time invalid - before minimum valid time", (int32_t)current_time);
        return 0;
    }

    /* Check if time was synchronized recently enough */
    time_t now = time(NULL);
    if (rtc_state.last_sync_time > 0 && difftime(now, rtc_state.last_sync_time) < 86400 * 30)
    {
        /* Time was synchronized in the last 30 days */
        return 1;
    }

    /* If hardware RTC reports a valid time, trust it */
    time_t hw_time;
    if (rtc_hw_get_time(&hw_time) == 0 && hw_time >= RTC_MIN_VALID_TIME)
    {
        return 1;
    }

    /* For simulation, assume time is valid if initialized and not in error state */
    return rtc_state.state == RTC_STATE_SYNCHRONIZED || rtc_state.state == RTC_STATE_INITIALIZED;
}

/**
 * Check if the RTC has backup power
 */
int rtc_has_backup_power(void)
{
    if (!rtc_state.initialized)
    {
        return 0;
    }

    /* Read battery voltage using ADC */
    float battery_voltage = read_backup_battery_voltage();

    /* Update the backup status */
    rtc_state.has_backup = (battery_voltage >= 2.7f); /* Typical threshold for coin cell */

    /* Log if backup power is lost */
    static int last_backup_state = -1;
    if (last_backup_state != rtc_state.has_backup)
    {
        if (last_backup_state >= 0)
        { /* Skip first update */
            if (rtc_state.has_backup)
            {
                rtc_log_event(RTC_EVENT_INIT, "RTC backup power restored", (int32_t)(battery_voltage * 1000));
            }
            else
            {
                rtc_log_event(RTC_EVENT_ERROR, "RTC backup power lost", (int32_t)(battery_voltage * 1000));
            }
        }
        last_backup_state = rtc_state.has_backup;
    }

    return rtc_state.has_backup;
}

/**
 * Get the RTC temperature
 */
float rtc_get_temperature(void)
{
    if (!rtc_state.initialized)
    {
        return -100.0f; /* Error indicator */
    }

    /* Read temperature registers from DS3231 */
    uint8_t temp_msb, temp_lsb;

    if (ds3231_read_register(DS3231_REG_TEMP_MSB, &temp_msb) == 0 &&
        ds3231_read_register(DS3231_REG_TEMP_LSB, &temp_lsb) == 0)
    {
        /* Convert to temperature (DS3231 format: MSB = whole degrees, LSB = fractional part) */
        rtc_state.temperature = (float)((int8_t)temp_msb) + ((temp_lsb >> 6) * 0.25f);

        /* Log unusual temperatures (below 0°C or above 50°C) */
        if (rtc_state.temperature < 0.0f || rtc_state.temperature > 50.0f)
        {
            rtc_log_event(RTC_EVENT_WARNING, "Unusual RTC temperature detected", (int32_t)(rtc_state.temperature * 100));
        }
    }
    else
    {
        /* For simulation, just use a simulated temperature if hardware read fails */
        /* In a real implementation, we might want to use the last known good value */
        rtc_state.temperature = 25.0f + (rand() % 100) / 100.0f - 0.5f; /* 24.5-25.5°C */
    }

    return rtc_state.temperature;
}

/**
 * Check for RTC tampering
 */
int rtc_check_for_tampering(void)
{
    if (!rtc_state.initialized)
    {
        return -1;
    }

    /* Read tamper detection register from DS3231 (if available) */
    uint8_t status_reg;
    if (ds3231_read_register(DS3231_REG_STATUS, &status_reg) != 0)
    {
        return -2;
    }

    /* Check if oscillator stop flag is set (indicates power loss) */
    if (status_reg & 0x80)
    {
        rtc_log_event(RTC_EVENT_TAMPER, "RTC power loss detected", status_reg);

        /* Update state */
        rtc_state.state = RTC_STATE_TAMPERED;
        rtc_state.error_count++;

        /* Clear the flag */
        status_reg &= ~0x80;
        ds3231_write_register(DS3231_REG_STATUS, status_reg);

        return 1; /* Tampering detected */
    }

    /* Check if battery voltage is too low */
    if (!rtc_has_backup_power())
    {
        rtc_log_event(RTC_EVENT_TAMPER, "RTC battery voltage too low", 0);
        return 2; /* Another form of tampering */
    }

    /* Check for sudden temperature changes, which might indicate physical tampering */
    static float last_temperature = 0.0f;
    static time_t last_temp_check = 0;
    time_t now = time(NULL);

    if (last_temp_check != 0)
    {
        float temp = rtc_get_temperature();
        float temp_change = fabs(temp - last_temperature);

        /* If temperature changed more than 5°C in less than 5 minutes, it's suspicious */
        if (temp_change > 5.0f && difftime(now, last_temp_check) < 300)
        {
            rtc_log_event(RTC_EVENT_TAMPER, "Suspicious temperature change detected", (int32_t)(temp_change * 100));
            rtc_state.error_count++;
            return 3; /* Possible physical tampering */
        }

        last_temperature = temp;
    }
    else
    {
        last_temperature = rtc_get_temperature();
    }

    last_temp_check = now;

    return 0; /* No tampering detected */
}

/**
 * Save RTC state to persistent storage
 */
int rtc_save_state(void)
{
    if (!rtc_state.initialized)
    {
        return -1;
    }

    /* Create a state structure with validation */
    typedef struct
    {
        rtc_state_enum_t state;
        time_t time_offset;
        time_t last_sync_time;
        int32_t drift_rate;
        uint32_t error_count;
        uint32_t crc;
    } rtc_saved_state_t;

    rtc_saved_state_t saved_state;
    saved_state.state = rtc_state.state;
    saved_state.time_offset = rtc_state.time_offset;
    saved_state.last_sync_time = rtc_state.last_sync_time;
    saved_state.drift_rate = rtc_state.drift_rate;
    saved_state.error_count = rtc_state.error_count;

    /* Calculate CRC over the state data */
    saved_state.crc = calculate_crc32(&saved_state, sizeof(rtc_saved_state_t) - sizeof(uint32_t));

    /* Save to non-volatile storage with wear-leveling */
    static uint8_t save_slot = 0;
    uint32_t slot_addr = RTC_STATE_ADDR + (save_slot * sizeof(rtc_saved_state_t));

    /* Rotate through 8 slots for wear-leveling */
    save_slot = (save_slot + 1) % 8;

    /* Save to flash memory */
    if (platform_flash_write(slot_addr, &saved_state, sizeof(rtc_saved_state_t)) != 0)
    {
        rtc_log_event(RTC_EVENT_ERROR, "Failed to save RTC state to flash", (int32_t)slot_addr);
        return -2;
    }

    /* Also save authentication token to a separate location */
    if (platform_flash_write(RTC_STATE_ADDR + 0x1000, rtc_state.auth_token, sizeof(rtc_state.auth_token)) != 0)
    {
        rtc_log_event(RTC_EVENT_ERROR, "Failed to save RTC auth token to flash", 0);
        return -3;
    }

    return 0;
}

/**
 * Load RTC state from persistent storage
 */
int rtc_load_state(void)
{
    /* Define state structure matching the saved format */
    typedef struct
    {
        rtc_state_enum_t state;
        time_t time_offset;
        time_t last_sync_time;
        int32_t drift_rate;
        uint32_t error_count;
        uint32_t crc;
    } rtc_saved_state_t;

    rtc_saved_state_t saved_state;
    int found_valid_state = 0;

    /* Check all 8 slots to find the most recent valid state */
    for (int slot = 0; slot < 8; slot++)
    {
        uint32_t slot_addr = RTC_STATE_ADDR + (slot * sizeof(rtc_saved_state_t));

        /* Read state from flash */
        if (platform_flash_read(slot_addr, &saved_state, sizeof(rtc_saved_state_t)) != 0)
        {
            continue; /* Try next slot */
        }

        /* Verify CRC */
        uint32_t calculated_crc = calculate_crc32(&saved_state, sizeof(rtc_saved_state_t) - sizeof(uint32_t));

        if (calculated_crc == saved_state.crc)
        {
            /* Found a valid state, copy relevant fields */
            rtc_state.state = saved_state.state;
            rtc_state.time_offset = saved_state.time_offset;
            rtc_state.last_sync_time = saved_state.last_sync_time;
            rtc_state.drift_rate = saved_state.drift_rate;
            rtc_state.error_count = saved_state.error_count;

            found_valid_state = 1;
            break;
        }
    }

    /* Try to load authentication token */
    if (platform_flash_read(RTC_STATE_ADDR + 0x1000, rtc_state.auth_token, sizeof(rtc_state.auth_token)) != 0)
    {
        /* If we can't load the token, generate a new one */
        generate_internal_auth_token(rtc_state.auth_token, sizeof(rtc_state.auth_token));
    }

    return found_valid_state ? 0 : -1;
}

/**
 * Synchronize RTC with an NTP server
 */
int rtc_sync_with_ntp(const char *ntp_server)
{
    if (!rtc_state.initialized || !ntp_server)
    {
        return -1;
    }

    /* Simulated NTP response - in a real implementation, this would contact the NTP server */
    if (strcmp(ntp_server, "pool.ntp.org") != 0 &&
        strcmp(ntp_server, "time.nist.gov") != 0 &&
        strcmp(ntp_server, "time.google.com") != 0)
    {
        rtc_log_event(RTC_EVENT_ERROR, "RTC sync failed - invalid NTP server", 0);
        return -2;
    }

    /* In a real implementation, this would call a network function to get NTP time */
    time_t ntp_time = time(NULL) + 1; /* Simulate a small time difference */

    /* Set RTC time with proper authentication */
    uint8_t auth_token[32];
    generate_internal_auth_token(auth_token, sizeof(auth_token));

    int result = rtc_set_time_auth(ntp_time, auth_token, sizeof(auth_token));

    if (result == 0)
    {
        rtc_log_event(RTC_EVENT_SYNC, "RTC synchronized with NTP server", (int32_t)ntp_time);
    }

    return result;
}

/**
 * Get RTC health information
 */
int rtc_get_health(rtc_health_t *health)
{
    if (!health)
    {
        return -1;
    }

    /* Fill health structure with current values */
    health->is_initialized = rtc_state.initialized;
    health->has_valid_time = rtc_has_valid_time();
    health->has_backup_power = rtc_has_backup_power();
    health->temperature = rtc_get_temperature();
    health->last_sync_time = rtc_state.last_sync_time;
    health->drift_rate = rtc_state.drift_rate;
    health->error_count = rtc_state.error_count;

    return 0;
}

/**
 * Run RTC self-test
 */
int rtc_run_self_test(void)
{
    if (!rtc_state.initialized)
    {
        return -1;
    }

    int result = 0;

    /* Check if RTC is running */
    time_t time1, time2;
    rtc_get_time(&time1);
    platform_delay_ms(1100); /* Sleep for just over 1 second */
    rtc_get_time(&time2);

    /* RTC should have advanced by roughly 1 second */
    double time_diff = difftime(time2, time1);
    if (time_diff < 0.9 || time_diff > 1.1)
    {
        rtc_log_event(RTC_EVENT_ERROR, "RTC timing error in self-test", (int32_t)(time_diff * 100));
        result |= 1; /* Set bit 0 for timing error */
    }

    /* Check backup power */
    if (!rtc_has_backup_power())
    {
        rtc_log_event(RTC_EVENT_ERROR, "RTC backup power failed in self-test", 0);
        result |= 2; /* Set bit 1 for backup power error */
    }

    /* Check for tampering */
    if (rtc_check_for_tampering() > 0)
    {
        result |= 4; /* Set bit 2 for tamper detection */
    }

    /* Check temperature sensor */
    float temp = rtc_get_temperature();
    if (temp < -40.0f || temp > 85.0f) /* DS3231 operating range */
    {
        rtc_log_event(RTC_EVENT_ERROR, "RTC temperature out of range in self-test", (int32_t)(temp * 100));
        result |= 8; /* Set bit 3 for temperature error */
    }

    /* Check if state can be saved and loaded */
    time_t original_offset = rtc_state.time_offset;
    rtc_state.time_offset = original_offset + 1000; /* Change offset temporarily */

    if (rtc_save_state() != 0 || rtc_load_state() != 0 || rtc_state.time_offset != original_offset + 1000)
    {
        rtc_log_event(RTC_EVENT_ERROR, "RTC state persistence failed in self-test", 0);
        result |= 16; /* Set bit 4 for state persistence error */
    }

    /* Restore original offset */
    rtc_state.time_offset = original_offset;
    rtc_save_state();

    return result;
}

/**
 * Verify an authenticated time source
 */
int rtc_verify_time_source(authenticated_time_t *auth_time, const uint8_t *public_key)
{
    /* This is a simulation - in a real implementation, you would verify the
     * digital signature of the timestamp+counter data
     */
    if (!auth_time || !public_key)
    {
        return -1;
    }

    /* Check that time is reasonable */
    if (auth_time->timestamp < RTC_MIN_VALID_TIME)
    {
        rtc_log_event(RTC_EVENT_ERROR, "Authentication failed - invalid time", (int32_t)auth_time->timestamp);
        return -2;
    }

    /* Real implementation would verify the signature here */
    /* For simulation, let's just accept any non-zero signature */
    int valid_sig = 0;
    for (int i = 0; i < 64; i++)
    {
        if (auth_time->signature[i] != 0)
        {
            valid_sig = 1;
            break;
        }
    }

    if (!valid_sig)
    {
        rtc_log_event(RTC_EVENT_ERROR, "Authentication failed - invalid signature", 0);
        return -3;
    }

    /* Set the time if signature is valid */
    rtc_set_time(auth_time->timestamp);

    rtc_log_event(RTC_EVENT_SYNC, "Time synchronized from authenticated source", (int32_t)auth_time->timestamp);

    return 0;
}

/**
 * Interface to hardware RTC (if available)
 */
int rtc_hw_get_time(time_t *t)
{
    if (!t)
    {
        return -1;
    }

    /* Read time registers from DS3231 */
    uint8_t seconds, minutes, hours, day, month, year;

    if (ds3231_read_register(DS3231_REG_SECONDS, &seconds) != 0 ||
        ds3231_read_register(DS3231_REG_MINUTES, &minutes) != 0 ||
        ds3231_read_register(DS3231_REG_HOURS, &hours) != 0 ||
        ds3231_read_register(DS3231_REG_DAY, &day) != 0 ||
        ds3231_read_register(DS3231_REG_MONTH, &month) != 0 ||
        ds3231_read_register(DS3231_REG_YEAR, &year) != 0)
    {
        /* For simulation, return a simulated time if hardware read fails */
        *t = time(NULL);
        return 0;
    }

    /* Convert BCD to binary */
    seconds = (seconds & 0x0F) + ((seconds >> 4) * 10);
    minutes = (minutes & 0x0F) + ((minutes >> 4) * 10);
    hours = (hours & 0x0F) + ((hours >> 4) * 10);
    day = (day & 0x0F) + ((day >> 4) * 10);
    month = (month & 0x0F) + ((month >> 4) * 10);
    year = (year & 0x0F) + ((year >> 4) * 10) + 2000; /* Assuming 21st century */

    /* Build time structure */
    struct tm time_components;
    time_components.tm_sec = seconds;
    time_components.tm_min = minutes;
    time_components.tm_hour = hours;
    time_components.tm_mday = day;
    time_components.tm_mon = month - 1;    /* mktime expects 0-11 */
    time_components.tm_year = year - 1900; /* mktime expects years since 1900 */

    /* Convert to time_t */
    *t = mktime(&time_components);

    return 0;
}

/**
 * Log an RTC event
 */
int rtc_log_event(rtc_event_type_t event_type, const char *details, int32_t value)
{
    if (!details)
    {
        return -1;
    }

    /* Get current time */
    time_t current_time = time(NULL);
    struct tm *time_info = localtime(&current_time);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", time_info);

    /* Log to secure storage or system log */
    printf("[%s] RTC %d: %s (%d)\n", timestamp, event_type, details, value);

    /* Store log in flash - in a real implementation, this would write to secure storage */
    typedef struct
    {
        time_t timestamp;
        rtc_event_type_t event_type;
        int32_t value;
        char details[32]; /* Fixed size for simplicity */
    } rtc_log_entry_t;

    static uint16_t log_index = 0;

    /* Read current log index */
    platform_flash_read(RTC_LOG_ADDR, &log_index, sizeof(log_index));

    /* Create log entry */
    rtc_log_entry_t entry;
    entry.timestamp = current_time;
    entry.event_type = event_type;
    entry.value = value;
    strncpy(entry.details, details, sizeof(entry.details) - 1);
    entry.details[sizeof(entry.details) - 1] = '\0';

    /* Store log entry with circular buffer approach */
    uint32_t entry_addr = RTC_LOG_ADDR + sizeof(log_index) +
                          (log_index % 100) * sizeof(rtc_log_entry_t);

    platform_flash_write(entry_addr, &entry, sizeof(rtc_log_entry_t));

    /* Update log index */
    log_index++;
    platform_flash_write(RTC_LOG_ADDR, &log_index, sizeof(log_index));

    return 0;
}

/* ========== Internal helper functions ========== */

/**
 * Verify RTC authentication token
 */
static int verify_rtc_auth_token(const uint8_t *token, size_t token_len)
{
    if (!token || token_len != sizeof(rtc_state.auth_token))
    {
        return 0; /* Invalid token */
    }

    /* Compare using constant-time comparison to prevent timing attacks */
    size_t equal = 1;
    for (size_t i = 0; i < token_len; i++)
    {
        equal &= (token[i] == rtc_state.auth_token[i]) ? 1 : 0;
    }

    return equal;
}

/**
 * Generate a new internal authentication token
 */
static void generate_internal_auth_token(uint8_t *token, size_t token_len)
{
    if (!token || token_len == 0)
    {
        return;
    }

    /* Generate random token */
    time_t now = time(NULL);
    for (size_t i = 0; i < token_len; i++)
    {
        /* Mix various entropy sources */
        token[i] = (uint8_t)((now + i + rand()) & 0xFF);
    }
}

/**
 * Calculate CRC32 checksum for data validation
 */
static uint32_t calculate_crc32(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFF;

    while (len--)
    {
        crc ^= *p++;
        for (int i = 0; i < 8; i++)
        {
            crc = (crc >> 1) ^ (-(int)(crc & 1) & 0xEDB88320);
        }
    }

    return ~crc;
}

/**
 * Read a DS3231 RTC register
 */
static int ds3231_read_register(uint8_t reg, uint8_t *value)
{
    if (!value)
    {
        return -1;
    }

    /* Simulated implementation - would use I2C in a real system */
    /* For simulation, we'll return fabricated values */

    switch (reg)
    {
    case DS3231_REG_SECONDS:
        *value = ((time(NULL) % 60) / 10) << 4 | ((time(NULL) % 60) % 10); /* BCD format */
        break;
    case DS3231_REG_MINUTES:
        *value = (((time(NULL) / 60) % 60) / 10) << 4 | (((time(NULL) / 60) % 60) % 10);
        break;
    case DS3231_REG_HOURS:
        *value = (((time(NULL) / 3600) % 24) / 10) << 4 | (((time(NULL) / 3600) % 24) % 10);
        break;
    case DS3231_REG_DAY:
        *value = 0x01; /* Placeholder */
        break;
    case DS3231_REG_MONTH:
        *value = 0x01; /* Placeholder */
        break;
    case DS3231_REG_YEAR:
        *value = 0x23; /* 2023 (BCD format) */
        break;
    case DS3231_REG_STATUS:
        *value = 0x00; /* No issues */
        break;
    case DS3231_REG_TEMP_MSB:
        *value = 25; /* 25°C */
        break;
    case DS3231_REG_TEMP_LSB:
        *value = 0; /* 0 fractional part */
        break;
    default:
        *value = 0;
        return -1;
    }

    return 0;
}

/**
 * Write to a DS3231 RTC register
 */
static int ds3231_write_register(uint8_t reg, uint8_t value)
{
    /* Simulated implementation - would use I2C in a real system */
    /* For simulation, we'll just validate the register and return success */

    /* Validate register address */
    if (reg > DS3231_REG_STATUS)
    {
        return -1;
    }

    return 0;
}

/**
 * Read the RTC backup battery voltage
 */
static float read_backup_battery_voltage(void)
{
    /* Simulated implementation - would use ADC in a real system */
    /* For simulation, we'll return a healthy battery voltage around 3V */
    static float battery_voltage = 3.0f;

    /* Simulate some battery discharge over time */
    static time_t last_check = 0;
    time_t now = time(NULL);

    if (last_check == 0)
    {
        last_check = now;
    }
    else
    {
        /* Discharge at rate of about 0.1V per week (very fast for simulation) */
        float discharge = (now - last_check) * 0.1f / (7 * 24 * 3600);
        battery_voltage -= discharge;

        /* Don't let it drop below 2.5V */
        if (battery_voltage < 2.5f)
        {
            battery_voltage = 2.5f;
        }

        last_check = now;
    }

    return battery_voltage;
}