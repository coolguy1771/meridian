#ifndef RTC_H
#define RTC_H

#include <stdint.h>
#include <time.h>

/**
 * @file rtc.h
 * @brief Real-time clock functions for secure time synchronization
 */

/**
 * Initialize the RTC subsystem
 * 
 * @return 0 on success, negative on error
 */
int rtc_init(void);

/**
 * Get the current time from the RTC
 * 
 * @param time Pointer to a time_t variable to receive the current time
 * @return 0 on success, negative on error
 */
int rtc_get_time(time_t *time);

/**
 * Set the RTC time
 * 
 * @param time The time value to set
 * @return 0 on success, negative on error
 */
int rtc_set_time(time_t time);

/**
 * Adjust the RTC time gradually
 * 
 * @param offset Time adjustment in seconds (can be negative)
 * @return 0 on success, negative on error
 */
int rtc_adjust_time(int32_t offset);

/**
 * Calculate time drift between local and peer time
 * 
 * @param peer_time Peer's timestamp
 * @param peer_counter Peer's message counter
 * @param local_counter Local message counter
 * @param avg_message_rate Average messages per second
 * @return Expected time difference in seconds
 */
int32_t rtc_calculate_drift(
    time_t peer_time,
    uint64_t peer_counter,
    uint64_t local_counter,
    float avg_message_rate);

/**
 * Check if the RTC has valid time
 * 
 * @return 1 if time is valid, 0 if not
 */
int rtc_has_valid_time(void);

/**
 * Check if the RTC has backup power
 * 
 * @return 1 if backup power is available, 0 if not
 */
int rtc_has_backup_power(void);

/**
 * Get the RTC temperature
 * 
 * @return Temperature in degrees Celsius, or negative on error
 */
float rtc_get_temperature(void);

#endif /* RTC_H */