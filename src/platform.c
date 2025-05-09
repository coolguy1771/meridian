#include "platform.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>

/**
 * Initialize the platform abstraction layer
 */
int platform_init(void)
{
    /* Seed the random number generator */
    srand(time(NULL));

    return 0;
}

/**
 * Get the platform type
 */
int platform_get_type(void)
{
    return PLATFORM_TYPE_LINUX;
}

/**
 * Delay for a specified number of milliseconds
 */
void platform_delay_ms(uint32_t ms)
{
    usleep(ms * 1000);
}

/**
 * Delay for a specified number of microseconds
 */
void platform_delay_us(uint32_t us)
{
    usleep(us);
}

/**
 * Get the current time in milliseconds
 */
uint32_t platform_get_time_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

/**
 * Get the current time in microseconds
 */
uint64_t platform_get_time_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000000ULL) + tv.tv_usec;
}

/**
 * Initialize a GPIO pin
 */
int platform_gpio_init(uint8_t pin, gpio_mode_t mode)
{
    /* Simulated implementation - would interact with hardware in reality */
    return 0;
}

/**
 * Set a GPIO pin value
 */
int platform_gpio_write(uint8_t pin, uint8_t value)
{
    /* Simulated implementation - would interact with hardware in reality */
    return 0;
}

/**
 * Read a GPIO pin value
 */
int platform_gpio_read(uint8_t pin)
{
    /* Simulated implementation - would interact with hardware in reality */
    return 0;
}

/**
 * Set up a GPIO interrupt
 */
int platform_gpio_set_interrupt(
    uint8_t pin,
    gpio_interrupt_t type,
    gpio_callback_t callback,
    void *arg)
{
    /* Simulated implementation - would interact with hardware in reality */
    return 0;
}

/**
 * Initialize SPI interface
 */
int platform_spi_init(
    uint8_t spi_num,
    uint8_t sck_pin,
    uint8_t mosi_pin,
    uint8_t miso_pin,
    spi_mode_t mode,
    uint32_t frequency)
{
    /* Simulated implementation - would interact with hardware in reality */
    return 0;
}

/**
 * Transfer data over SPI
 */
int platform_spi_transfer(
    uint8_t spi_num,
    const uint8_t *tx_data,
    uint8_t *rx_data,
    size_t len)
{
    /* Simulated implementation - would interact with hardware in reality */
    if (rx_data)
    {
        /* For simulation, just echo back the data */
        memcpy(rx_data, tx_data, len);
    }
    return 0;
}

/**
 * Start a timer with callback
 */
int platform_timer_start(
    uint8_t timer_num,
    uint32_t interval_ms,
    uint8_t periodic,
    timer_callback_t callback,
    void *arg)
{
    /* Simulated implementation - would interact with hardware in reality */
    return 0;
}

/**
 * Stop a timer
 */
int platform_timer_stop(uint8_t timer_num)
{
    /* Simulated implementation - would interact with hardware in reality */
    return 0;
}

/**
 * Read from flash memory
 */
int platform_flash_read(uint32_t addr, void *data, size_t len)
{
    /* Simulated implementation - would interact with hardware in reality */
    memset(data, 0, len); /* Initialize with zeros for simulation */
    return 0;
}

/**
 * Write to flash memory
 */
int platform_flash_write(uint32_t addr, const void *data, size_t len)
{
    /* Simulated implementation - would interact with hardware in reality */
    return 0;
}

/**
 * Erase flash sector
 */
int platform_flash_erase_sector(uint32_t sector)
{
    /* Simulated implementation - would interact with hardware in reality */
    return 0;
}

/**
 * Get random bytes
 */
int platform_random_bytes(void *buffer, size_t len)
{
    uint8_t *buf = (uint8_t *)buffer;

    for (size_t i = 0; i < len; i++)
    {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }

    return 0;
}

/**
 * Enter deep sleep mode
 */
int platform_deep_sleep(uint32_t sleep_ms)
{
    /* Simulated implementation - would interact with hardware in reality */
    /* For simulation, just sleep for the requested time */
    if (sleep_ms > 0)
    {
        usleep(sleep_ms * 1000);
    }
    return 0;
}

/**
 * Get system reset reason
 */
int platform_get_reset_reason(void)
{
    /* Simulated implementation - would interact with hardware in reality */
    return 0; /* Normal boot */
}

/**
 * Get battery voltage
 */
int platform_get_battery_mv(void)
{
    /* Simulated implementation - would interact with hardware in reality */
    return 3800; /* Simulated battery voltage: 3.8V */
}

/**
 * Get unique device ID
 */
int platform_get_unique_id(uint8_t *id_buffer, size_t max_len)
{
    if (!id_buffer || max_len < 8)
    {
        return -1;
    }

    /* Simulated implementation - would read hardware ID in reality */
    static const uint8_t simulated_id[8] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};

    size_t copy_len = (max_len < sizeof(simulated_id)) ? max_len : sizeof(simulated_id);
    memcpy(id_buffer, simulated_id, copy_len);

    return copy_len;
}

/**
 * Get hardware-based random bytes
 */
int platform_get_hardware_entropy(uint8_t *buffer, size_t len)
{
    if (!buffer || len == 0)
    {
        return -1;
    }

    /* Simulated implementation - would use hardware RNG in reality */
    /* For simulation, we'll just use a simple algorithm based on timing jitter */
    struct timeval tv;
    unsigned int seed = 0;

    for (size_t i = 0; i < len; i++)
    {
        gettimeofday(&tv, NULL);
        seed ^= (tv.tv_sec ^ tv.tv_usec);

        /* Introduce artificial delays to get timing variations */
        for (volatile int j = 0; j < (seed % 100); j++)
            ;

        gettimeofday(&tv, NULL);
        buffer[i] = (tv.tv_usec & 0xFF) ^ (seed & 0xFF);

        /* Update seed for next iteration */
        seed = (seed << 1) | (seed >> 31);
        seed ^= buffer[i];
    }

    return 0;
}

/**
 * Get current CPU cycle count
 */
uint32_t platform_get_cpu_cycles(void)
{
    /* Simulated implementation - would use hardware cycle counter in reality */
    /* For simulation, use microsecond timer */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000000) + tv.tv_usec;
}

/**
 * Store a key in the secure element or HSM
 */
int platform_store_secure_key(uint8_t key_id, const uint8_t *key_data, size_t key_len)
{
    if (!key_data || key_len == 0 || key_id > 10)
    {
        return -1;
    }

    /* Simulated implementation - would use HSM or secure element in reality */
    /* For simulation, just verify the key is valid */
    int zero_bytes = 0;
    for (size_t i = 0; i < key_len; i++)
    {
        if (key_data[i] == 0)
        {
            zero_bytes++;
        }
    }

    /* Reject keys that are all zeros or have too many zeros */
    if (zero_bytes == key_len || zero_bytes > (key_len * 3 / 4))
    {
        return -2;
    }

    return 0;
}

/**
 * Log a message with specified severity level
 */
int platform_log(uint8_t level, const char *format, ...)
{
    static const char *level_names[] = {
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
        "CRITICAL"};

    if (!format || level > LOG_LEVEL_CRITICAL)
    {
        return -1;
    }

    /* Simulated implementation - would use logging infrastructure in reality */
    /* For simulation, output to stderr */
    va_list args;
    struct timeval tv;

    gettimeofday(&tv, NULL);

    fprintf(stderr, "[%ld.%06ld] %s: ", tv.tv_sec, tv.tv_usec, level_names[level]);

    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    fprintf(stderr, "\n");
    fflush(stderr);

    return 0;
}