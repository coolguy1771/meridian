#ifndef RTC_H
#define RTC_H

#include <stdint.h>
#include <time.h>
#include <stddef.h> /* For size_t */

/**
 * @file rtc.h
 * @brief Real-time clock functions for secure time synchronization
 */

/* RTC state definitions */
typedef enum
{
    RTC_STATE_UNINITIALIZED = 0,
    RTC_STATE_INITIALIZED = 1,
    RTC_STATE_SYNCHRONIZED = 2,
    RTC_STATE_ERROR = 3,
    RTC_STATE_TAMPERED = 4
} rtc_state_enum_t;

/* RTC event types for logging */
typedef enum
{
    RTC_EVENT_INIT = 0,
    RTC_EVENT_SET_TIME = 1,
    RTC_EVENT_ADJUST_TIME = 2,
    RTC_EVENT_SYNC = 3,
    RTC_EVENT_ERROR = 4,
    RTC_EVENT_TAMPER = 5,
    RTC_EVENT_WARNING = 6
} rtc_event_type_t;

/* RTC health information structure */
typedef struct
{
    int is_initialized;
    int has_valid_time;
    int has_backup_power;
    float temperature;
    time_t last_sync_time;
    int32_t drift_rate;
    uint32_t error_count;
} rtc_health_t;

/* Authenticated time structure */
typedef struct
{
    time_t timestamp;
    uint64_t counter;
    uint8_t signature[64]; /* Digital signature */
} authenticated_time_t;

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
 * @param new_time The time value to set
 * @return 0 on success, negative on error
 */
int rtc_set_time(time_t new_time);

/**
 * Set the RTC time with authentication
 *
 * @param new_time The time value to set
 * @param auth_token Authentication token to authorize time change
 * @param token_len Length of authentication token
 * @return 0 on success, negative on error
 */
int rtc_set_time_auth(time_t new_time, const uint8_t *auth_token, size_t token_len);

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

/**
 * Verify an authenticated time source
 *
 * @param auth_time Authenticated time structure
 * @param public_key Public key for signature verification
 * @return 0 on success, negative on error
 */
int rtc_verify_time_source(authenticated_time_t *auth_time, const uint8_t *public_key);

/**
 * Save RTC state to persistent storage
 *
 * @return 0 on success, negative on error
 */
int rtc_save_state(void);

/**
 * Load RTC state from persistent storage
 *
 * @return 0 on success, negative on error
 */
int rtc_load_state(void);

/**
 * Synchronize RTC with an NTP server
 *
 * @param ntp_server NTP server hostname or IP address
 * @return 0 on success, negative on error
 */
int rtc_sync_with_ntp(const char *ntp_server);

/**
 * Log an RTC event
 *
 * @param event_type Type of event
 * @param details Text description of the event
 * @param value Numeric value associated with the event
 * @return 0 on success, negative on error
 */
int rtc_log_event(rtc_event_type_t event_type, const char *details, int32_t value);

/**
 * Check for RTC tampering
 *
 * @return 0 if no tampering detected, 1 if tampering detected, negative on error
 */
int rtc_check_for_tampering(void);

/**
 * Get RTC health information
 *
 * @param health Pointer to health structure to fill
 * @return 0 on success, negative on error
 */
int rtc_get_health(rtc_health_t *health);

/**
 * Run RTC self-test
 *
 * @return 0 if all tests pass, bitmask of failed tests, negative on error
 */
int rtc_run_self_test(void);

/**
 * Interface to hardware RTC (if available)
 *
 * @param t Pointer to store time
 * @return 0 on success, negative on error
 */
int rtc_hw_get_time(time_t *t);

#endif /* RTC_H */