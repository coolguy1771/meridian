#include "rtc.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/* Module state */
static struct
{
    int initialized;
    int has_backup;
    time_t time_offset; /* Offset between RTC time and system time */
    float temperature;
} rtc_state;

/**
 * Initialize the RTC subsystem
 */
int rtc_init(void)
{
    /* In a real implementation, this would initialize the DS3231 RTC */
    /* For this simulation, we'll just use the system clock */

    rtc_state.initialized = 1;
    rtc_state.has_backup = 1; /* Assume we have backup power */
    rtc_state.time_offset = 0;
    rtc_state.temperature = 25.0f; /* Room temperature */

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

    /* Calculate the offset from system time */
    rtc_state.time_offset = new_time - time(NULL);

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

    /* Apply a fraction of the offset to avoid large jumps */
    int32_t adjustment = offset / 4; /* Apply 25% of the requested adjustment */

    if (adjustment == 0)
    {
        /* Ensure we make at least a small adjustment */
        adjustment = (offset > 0) ? 1 : -1;
    }

    rtc_state.time_offset += adjustment;

    return 0;
}

/**
 * Calculate time drift between local and peer time
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

    /* Calculate expected time difference based on counter difference */
    int64_t counter_diff = (int64_t)peer_counter - (int64_t)local_counter;
    int32_t expected_time_diff = (int32_t)(counter_diff / avg_message_rate);

    /* Get current local time */
    time_t local_time;
    rtc_get_time(&local_time);

    /* Calculate actual time difference */
    int32_t actual_time_diff = (int32_t)difftime(local_time, peer_time);

    /* The drift is the difference between actual and expected */
    return actual_time_diff - expected_time_diff;
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

    /* In a real implementation, this would check if the RTC has been set */
    /* For this simulation, we'll assume it's valid if initialized */
    return 1;
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

    /* In a real implementation, this would check the backup power source */
    /* For this simulation, we'll use the static value */
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

    /* In a real implementation, this would read from the DS3231 temperature register */
    /* For this simulation, we'll return the static value */
    return rtc_state.temperature;
}