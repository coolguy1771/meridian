#ifndef PLATFORM_H
#define PLATFORM_H

#include <stdint.h>
#include <stddef.h>

/* Log levels */
#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO 1
#define LOG_LEVEL_WARNING 2
#define LOG_LEVEL_ERROR 3
#define LOG_LEVEL_CRITICAL 4

/* Secure key identifiers */
#define SECURE_KEY_DEVICE_SECRET 0
#define SECURE_KEY_IDENTITY_PRIVATE 1
#define SECURE_KEY_IDENTITY_PUBLIC 2

/**
 * @file platform.h
 * @brief Platform-specific functions and abstraction layer
 */

/* Platform types */
#define PLATFORM_TYPE_UNKNOWN 0
#define PLATFORM_TYPE_ESP32 1
#define PLATFORM_TYPE_LINUX 2
#define PLATFORM_TYPE_STM32 3

/* GPIO definitions */
typedef enum
{
    GPIO_MODE_INPUT,
    GPIO_MODE_OUTPUT,
    GPIO_MODE_INPUT_PULLUP,
    GPIO_MODE_INPUT_PULLDOWN,
    GPIO_MODE_ANALOG
} gpio_mode_t;

typedef enum
{
    GPIO_INT_DISABLE,
    GPIO_INT_RISING,
    GPIO_INT_FALLING,
    GPIO_INT_CHANGE
} gpio_interrupt_t;

/* SPI mode definitions */
typedef enum
{
    SPI_MODE0, /* CPOL=0, CPHA=0 */
    SPI_MODE1, /* CPOL=0, CPHA=1 */
    SPI_MODE2, /* CPOL=1, CPHA=0 */
    SPI_MODE3  /* CPOL=1, CPHA=1 */
} spi_mode_t;

/* Timer callback function type */
typedef void (*timer_callback_t)(void *arg);

/* GPIO callback function type */
typedef void (*gpio_callback_t)(void *arg);

/**
 * Initialize the platform abstraction layer
 *
 * @return 0 on success, negative on error
 */
int platform_init(void);

/**
 * Get the platform type
 *
 * @return Platform type (PLATFORM_TYPE_*)
 */
int platform_get_type(void);

/**
 * Delay for a specified number of milliseconds
 *
 * @param ms Milliseconds to delay
 */
void platform_delay_ms(uint32_t ms);

/**
 * Delay for a specified number of microseconds
 *
 * @param us Microseconds to delay
 */
void platform_delay_us(uint32_t us);

/**
 * Get the current time in milliseconds
 *
 * @return Current time in milliseconds since boot
 */
uint32_t platform_get_time_ms(void);

/**
 * Get the current time in microseconds
 *
 * @return Current time in microseconds since boot
 */
uint64_t platform_get_time_us(void);

/**
 * Initialize a GPIO pin
 *
 * @param pin Pin number
 * @param mode Pin mode
 * @return 0 on success, negative on error
 */
int platform_gpio_init(uint8_t pin, gpio_mode_t mode);

/**
 * Set a GPIO pin value
 *
 * @param pin Pin number
 * @param value Pin value (0 or 1)
 * @return 0 on success, negative on error
 */
int platform_gpio_write(uint8_t pin, uint8_t value);

/**
 * Read a GPIO pin value
 *
 * @param pin Pin number
 * @return Pin value (0 or 1), or negative on error
 */
int platform_gpio_read(uint8_t pin);

/**
 * Set up a GPIO interrupt
 *
 * @param pin Pin number
 * @param type Interrupt type
 * @param callback Function to call when interrupt occurs
 * @param arg Argument to pass to callback
 * @return 0 on success, negative on error
 */
int platform_gpio_set_interrupt(
    uint8_t pin,
    gpio_interrupt_t type,
    gpio_callback_t callback,
    void *arg);

/**
 * Initialize SPI interface
 *
 * @param spi_num SPI interface number
 * @param sck_pin SCK pin
 * @param mosi_pin MOSI pin
 * @param miso_pin MISO pin
 * @param mode SPI mode
 * @param frequency Clock frequency in Hz
 * @return 0 on success, negative on error
 */
int platform_spi_init(
    uint8_t spi_num,
    uint8_t sck_pin,
    uint8_t mosi_pin,
    uint8_t miso_pin,
    spi_mode_t mode,
    uint32_t frequency);

/**
 * Transfer data over SPI
 *
 * @param spi_num SPI interface number
 * @param tx_data Data to transmit
 * @param rx_data Buffer to receive data
 * @param len Length of data to transfer
 * @return 0 on success, negative on error
 */
int platform_spi_transfer(
    uint8_t spi_num,
    const uint8_t *tx_data,
    uint8_t *rx_data,
    size_t len);

/**
 * Start a timer with callback
 *
 * @param timer_num Timer number
 * @param interval_ms Timer interval in milliseconds
 * @param periodic 1 for periodic timer, 0 for one-shot
 * @param callback Function to call when timer expires
 * @param arg Argument to pass to callback
 * @return 0 on success, negative on error
 */
int platform_timer_start(
    uint8_t timer_num,
    uint32_t interval_ms,
    uint8_t periodic,
    timer_callback_t callback,
    void *arg);

/**
 * Stop a timer
 *
 * @param timer_num Timer number
 * @return 0 on success, negative on error
 */
int platform_timer_stop(uint8_t timer_num);

/**
 * Read from flash memory
 *
 * @param addr Address to read from
 * @param data Buffer to read into
 * @param len Length of data to read
 * @return 0 on success, negative on error
 */
int platform_flash_read(uint32_t addr, void *data, size_t len);

/**
 * Write to flash memory
 *
 * @param addr Address to write to
 * @param data Data to write
 * @param len Length of data to write
 * @return 0 on success, negative on error
 */
int platform_flash_write(uint32_t addr, const void *data, size_t len);

/**
 * Erase flash sector
 *
 * @param sector Sector number to erase
 * @return 0 on success, negative on error
 */
int platform_flash_erase_sector(uint32_t sector);

/**
 * Get random bytes
 *
 * @param buffer Buffer to fill with random bytes
 * @param len Number of random bytes to generate
 * @return 0 on success, negative on error
 */
int platform_random_bytes(void *buffer, size_t len);

/**
 * Enter deep sleep mode
 *
 * @param sleep_ms Time to sleep in milliseconds (0 for indefinite)
 * @return 0 on success, negative on error
 */
int platform_deep_sleep(uint32_t sleep_ms);

/**
 * Get system reset reason
 *
 * @return Reset reason code
 */
int platform_get_reset_reason(void);

/**
 * Get battery voltage
 *
 * @return Battery voltage in millivolts, or negative on error
 */
int platform_get_battery_mv(void);

/**
 * Get unique device ID
 *
 * @param id_buffer Buffer to store device ID (at least 8 bytes)
 * @param max_len Maximum buffer length
 * @return Length of ID copied, or negative on error
 */
int platform_get_unique_id(uint8_t *id_buffer, size_t max_len);

/**
 * Get hardware-based random bytes
 *
 * @param buffer Buffer to fill with entropy
 * @param len Number of bytes to generate
 * @return 0 on success, negative on error
 */
int platform_get_hardware_entropy(uint8_t *buffer, size_t len);

/**
 * Get current CPU cycle count
 *
 * @return Current CPU cycle count
 */
uint32_t platform_get_cpu_cycles(void);

/**
 * Store a key in the secure element or HSM
 *
 * @param key_id Key identifier
 * @param key_data Key data buffer
 * @param key_len Key length in bytes
 * @return 0 on success, negative on error
 */
int platform_store_secure_key(uint8_t key_id, const uint8_t *key_data, size_t key_len);

/**
 * Log a message with specified severity level
 *
 * @param level Severity level (LOG_LEVEL_XXX)
 * @param format Printf-style format string
 * @param ... Variable arguments for the format string
 * @return 0 on success, negative on error
 */
int platform_log(uint8_t level, const char *format, ...);

#endif /* PLATFORM_H */