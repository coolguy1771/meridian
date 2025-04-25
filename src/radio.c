#include "radio.h"
#include "platform.h"
#include "packet.h"
#include <string.h>
#include <stdlib.h>

/**
 * @file radio.c
 * @brief SX126x LoRa radio driver implementation
 *
 * This file implements a driver for the Semtech SX126x LoRa radio transceivers.
 * It provides APIs for radio initialization, configuration, transmission, reception,
 * and channel management. The implementation supports multiple frequency bands
 * (433MHz, 868MHz, 915MHz) and configurable radio parameters.
 */

/* SPI interface to the radio */
#define RADIO_SPI_INTERFACE 0

/* GPIO pins for radio control */
#define RADIO_NSS_PIN 10  /* SPI chip select */
#define RADIO_RESET_PIN 9 /* Reset signal */
#define RADIO_BUSY_PIN 8  /* Busy signal */
#define RADIO_DIO1_PIN 7  /* Interrupt signal */

/* SX126x register addresses and commands */
#define RADIO_CMD_SET_SLEEP 0x84
#define RADIO_CMD_SET_STANDBY 0x80
#define RADIO_CMD_SET_FS 0xC1
#define RADIO_CMD_SET_TX 0x83
#define RADIO_CMD_SET_RX 0x82
#define RADIO_CMD_STOP_TIMER_ON_PREAMBLE 0x9F
#define RADIO_CMD_SET_CAD 0xC5
#define RADIO_CMD_SET_TX_CONTINUOUS_WAVE 0xD1
#define RADIO_CMD_SET_TX_INFINITE_PREAMBLE 0xD2
#define RADIO_CMD_SET_REGULATOR_MODE 0x96
#define RADIO_CMD_SET_RF_FREQUENCY 0x86
#define RADIO_CMD_CALIBRATE 0x89
#define RADIO_CMD_CALIBRATE_IMAGE 0x98
#define RADIO_CMD_SET_PA_CONFIG 0x95
#define RADIO_CMD_SET_TX_PARAMS 0x8E
#define RADIO_CMD_SET_PACKET_TYPE 0x8A
#define RADIO_CMD_SET_MODULATION_PARAMS 0x8B
#define RADIO_CMD_SET_PACKET_PARAMS 0x8C
#define RADIO_CMD_SET_CAD_PARAMS 0x88
#define RADIO_CMD_SET_BUFFER_BASE_ADDRESS 0x8F
#define RADIO_CMD_SET_IRQ_MASK 0x02
#define RADIO_CMD_CLEAR_IRQ_STATUS 0x12
#define RADIO_CMD_GET_IRQ_STATUS 0x15
#define RADIO_CMD_GET_RX_BUFFER_STATUS 0x17
#define RADIO_CMD_GET_PACKET_STATUS 0x1D
#define RADIO_CMD_GET_RSSI_INST 0x1F
#define RADIO_CMD_SET_LORA_SYMB_TIMEOUT 0xA0
#define RADIO_CMD_WRITE_REGISTER 0x0D
#define RADIO_CMD_READ_REGISTER 0x1D
#define RADIO_CMD_WRITE_BUFFER 0x0E
#define RADIO_CMD_READ_BUFFER 0x1E
#define RADIO_CMD_SET_DIO_IRQ_PARAMS 0x08
#define RADIO_CMD_GET_STATS 0x10
#define RADIO_CMD_RESET_STATS 0x00

/* Registers addresses */
#define RADIO_REG_LORA_SYNC_WORD 0x0740

/* IRQ definitions */
#define RADIO_IRQ_TX_DONE 0x0001
#define RADIO_IRQ_RX_DONE 0x0002
#define RADIO_IRQ_TIMEOUT 0x0004
#define RADIO_IRQ_SYNC_WORD_VALID 0x0008
#define RADIO_IRQ_HEADER_VALID 0x0010
#define RADIO_IRQ_HEADER_ERROR 0x0020
#define RADIO_IRQ_CRC_ERROR 0x0040
#define RADIO_IRQ_CAD_DONE 0x0080
#define RADIO_IRQ_CAD_DETECTED 0x0100
#define RADIO_IRQ_PREAMBLE_DETECTED 0x0200

/* Packet type definition */
#define RADIO_PACKET_TYPE_GFSK 0x00
#define RADIO_PACKET_TYPE_LORA 0x01

/* LoRa bandwidth options */
#define RADIO_BANDWIDTH_7 0x00
#define RADIO_BANDWIDTH_10 0x01
#define RADIO_BANDWIDTH_15 0x02
#define RADIO_BANDWIDTH_20 0x03
#define RADIO_BANDWIDTH_31 0x04
#define RADIO_BANDWIDTH_41 0x05
#define RADIO_BANDWIDTH_62 0x06
#define RADIO_BANDWIDTH_125 0x07
#define RADIO_BANDWIDTH_250 0x08
#define RADIO_BANDWIDTH_500 0x09

/* LoRa coding rate denominator options */
#define RADIO_CODING_RATE_4_5 0x01
#define RADIO_CODING_RATE_4_6 0x02
#define RADIO_CODING_RATE_4_7 0x03
#define RADIO_CODING_RATE_4_8 0x04

/* Power amplifier selection */
#define RADIO_PA_RFO 0x00
#define RADIO_PA_BOOST 0x01

/* Maximum buffer size */
#define RADIO_MAX_BUFFER_SIZE 255

/**
 * Radio driver state structure
 *
 * This structure maintains the internal state of the radio driver, including:
 * - Current operating state (idle, rx, tx, etc.)
 * - Configuration parameters
 * - Callback functions for events
 * - Statistics and signal information
 * - Buffer for packet data
 */
static struct
{
    uint8_t state;                         /* Current radio state (IDLE, RX, TX, etc.) */
    radio_config_t config;                 /* Current radio configuration */
    radio_rx_callback_t rx_callback;       /* Callback for received packets */
    radio_tx_callback_t tx_callback;       /* Callback for completed transmissions */
    radio_error_callback_t error_callback; /* Callback for radio errors */
    int16_t last_rssi;                     /* Last measured RSSI value in dBm */
    int8_t last_snr;                       /* Last measured SNR value in dB */
    uint32_t tx_count;                     /* Count of transmitted packets */
    uint32_t rx_count;                     /* Count of received packets */
    uint32_t error_count;                  /* Count of errors encountered */
    uint8_t buffer[RADIO_MAX_BUFFER_SIZE]; /* Buffer for packet data */
} radio_state;

/* Forward declarations for internal functions */
/**
 * Wait for the BUSY pin to go low, indicating the radio is ready
 * @return 0 on success, negative value on error
 */
static int radio_wait_on_busy(void);
/**
 * Writes data to a radio register
 * @param addr Register address
 * @param data Pointer to data to write
 * @param len Length of data in bytes
 * @return 0 on success, negative value on error
 */
static int radio_write_register(uint16_t addr, uint8_t *data, size_t len);

/**
 * Reads data from a radio register
 * @param addr Register address
 * @param data Pointer to buffer to store read data
 * @param len Length of data to read in bytes
 * @return 0 on success, negative value on error
 */
static int radio_read_register(uint16_t addr, uint8_t *data, size_t len);

/**
 * Sends a command to the radio
 * @param cmd Command opcode
 * @param data Pointer to command data (can be NULL)
 * @param len Length of command data in bytes (can be 0)
 * @return 0 on success, negative value on error
 */
static int radio_send_command(uint8_t cmd, uint8_t *data, size_t len);

/**
 * Interrupt handler for radio events
 * @param arg User-provided argument (unused)
 */
static void radio_handle_interrupt(void *arg);

/**
 * Configures the LoRa modulation parameters
 * @return 0 on success, negative value on error
 */
static int radio_set_lora_modulation(void);

/**
 * Configures the LoRa packet parameters
 * @return 0 on success, negative value on error
 */
static int radio_set_lora_packet_params(void);

/**
 * Reads a received packet from the radio
 * @param buffer Buffer to store packet data
 * @param size Pointer to variable that will hold packet size
 * @param rssi Pointer to variable that will hold RSSI value
 * @param snr Pointer to variable that will hold SNR value
 * @return 0 on success, negative value on error
 */
static int radio_read_packet(uint8_t *buffer, size_t *size, int16_t *rssi, int8_t *snr);

/**
 * Initialize the radio hardware
 *
 * This function initializes the SX126x radio, configuring the hardware
 * interfaces (SPI, GPIOs), resetting the device, and applying the initial
 * configuration settings.
 *
 * @param config Pointer to radio configuration structure
 * @return 0 on success, negative value on error
 */
int radio_init(const radio_config_t *config)
{
    if (!config)
    {
        return -1;
    }

    /* Initialize state */
    memset(&radio_state, 0, sizeof(radio_state));
    radio_state.state = RADIO_STATE_IDLE;
    radio_state.config = *config;

    /* Initialize GPIO */
    platform_gpio_init(RADIO_NSS_PIN, GPIO_MODE_OUTPUT);
    platform_gpio_init(RADIO_RESET_PIN, GPIO_MODE_OUTPUT);
    platform_gpio_init(RADIO_BUSY_PIN, GPIO_MODE_INPUT);
    platform_gpio_init(RADIO_DIO1_PIN, GPIO_MODE_INPUT);

    /* Set up radio interrupt */
    platform_gpio_set_interrupt(RADIO_DIO1_PIN, GPIO_INT_RISING, radio_handle_interrupt, NULL);

    /* Initialize SPI interface */
    platform_spi_init(RADIO_SPI_INTERFACE,
                      /* SCK, MOSI, MISO pins would be defined in the actual platform */
                      0, 0, 0,
                      SPI_MODE0,
                      10000000); /* 10 MHz SPI clock */

    /* Reset the radio module */
    platform_gpio_write(RADIO_RESET_PIN, 0);
    platform_delay_ms(10);
    platform_gpio_write(RADIO_RESET_PIN, 1);
    platform_delay_ms(10);

    /* Wait for radio to be ready */
    while (platform_gpio_read(RADIO_BUSY_PIN))
    {
        platform_delay_ms(1);
    }

    /* Set standby mode RC */
    uint8_t standby_cmd = 0x00; /* RC oscillator */
    radio_send_command(RADIO_CMD_SET_STANDBY, &standby_cmd, 1);

    /* Configure DIO pins */
    uint8_t dio_params[8];
    uint16_t irq_mask = RADIO_IRQ_TX_DONE | RADIO_IRQ_RX_DONE | RADIO_IRQ_TIMEOUT |
                        RADIO_IRQ_CRC_ERROR | RADIO_IRQ_CAD_DONE | RADIO_IRQ_CAD_DETECTED |
                        RADIO_IRQ_PREAMBLE_DETECTED;

    dio_params[0] = (uint8_t)(irq_mask & 0xFF);        /* IRQ mask LSB */
    dio_params[1] = (uint8_t)((irq_mask >> 8) & 0xFF); /* IRQ mask MSB */
    dio_params[2] = (uint8_t)(irq_mask & 0xFF);        /* DIO1 mask LSB */
    dio_params[3] = (uint8_t)((irq_mask >> 8) & 0xFF); /* DIO1 mask MSB */
    dio_params[4] = 0;                                 /* DIO2 mask LSB */
    dio_params[5] = 0;                                 /* DIO2 mask MSB */
    dio_params[6] = 0;                                 /* DIO3 mask LSB */
    dio_params[7] = 0;                                 /* DIO3 mask MSB */

    radio_send_command(RADIO_CMD_SET_DIO_IRQ_PARAMS, dio_params, 8);

    /* Set packet type to LoRa */
    uint8_t packet_type = RADIO_PACKET_TYPE_LORA;
    radio_send_command(RADIO_CMD_SET_PACKET_TYPE, &packet_type, 1);

    /* Configure the radio with initial settings */
    if (radio_set_config(config) != 0)
    {
        return -2;
    }

    /* Set LoRa sync word (0x3444 is private network) */
    uint8_t sync_word[2] = {0x34, 0x44};
    radio_write_register(RADIO_REG_LORA_SYNC_WORD, sync_word, 2);

    /* Set buffer base addresses */
    uint8_t buf_addr[2] = {0, 0}; /* TX base address, RX base address */
    radio_send_command(RADIO_CMD_SET_BUFFER_BASE_ADDRESS, buf_addr, 2);

    return 0;
}

/**
 * Set the radio configuration
 *
 * This function updates the radio's configuration parameters including frequency,
 * modulation settings, packet parameters, and power settings. It applies the
 * settings directly to the hardware.
 *
 * @param config Pointer to radio configuration structure
 * @return 0 on success, negative value on error
 */
int radio_set_config(const radio_config_t *config)
{
    if (!config)
    {
        return -1;
    }

    /* Update state */
    radio_state.config = *config;

    /* Set the radio to standby mode first */
    uint8_t standby_cmd = 0x00; /* RC oscillator */
    radio_send_command(RADIO_CMD_SET_STANDBY, &standby_cmd, 1);

    /* Wait for radio to be ready */
    while (platform_gpio_read(RADIO_BUSY_PIN))
    {
        platform_delay_ms(1);
    }

    /* Set frequency */
    uint8_t freq_bytes[4];
    /* SX126x specific frequency calculation */
    uint32_t freq_reg = (uint32_t)((double)config->frequency / (double)32000000 * (double)(1 << 25)); /* 32MHz XTAL */
    freq_bytes[0] = (freq_reg >> 24) & 0xFF;
    freq_bytes[1] = (freq_reg >> 16) & 0xFF;
    freq_bytes[2] = (freq_reg >> 8) & 0xFF;
    freq_bytes[3] = freq_reg & 0xFF;

    /* Set RF frequency using the correct SX126x command */
    radio_send_command(RADIO_CMD_SET_RF_FREQUENCY, freq_bytes, 4);

    /* Configure PA (Power Amplifier) */
    uint8_t pa_config[4];
    pa_config[0] = 0x04; /* PA duty cycle */
    pa_config[1] = 0x07; /* HPOWER */
    pa_config[2] = 0x00; /* Device select (0: RFO, 1: BOOST) */
    pa_config[3] = 0x01; /* PA LUT config */

    radio_send_command(RADIO_CMD_SET_PA_CONFIG, pa_config, 4);

    /* Set TX parameters (power, ramp time) */
    uint8_t tx_params[2];
    tx_params[0] = config->txPower & 0xFF;
    tx_params[1] = 0x04; /* Default ramp time (40us) */

    radio_send_command(RADIO_CMD_SET_TX_PARAMS, tx_params, 2);

    /* Set LoRa modulation parameters */
    if (radio_set_lora_modulation() != 0)
    {
        return -2;
    }

    /* Set LoRa packet parameters */
    if (radio_set_lora_packet_params() != 0)
    {
        return -3;
    }

    /* Clear IRQ status */
    uint8_t clear_irq[2] = {0xFF, 0xFF}; /* Clear all IRQs */
    radio_send_command(RADIO_CMD_CLEAR_IRQ_STATUS, clear_irq, 2);

    return 0;
}

/**
 * Get the current radio configuration
 *
 * This function retrieves the radio's current configuration parameters
 * from the internal state. It does not read directly from the hardware.
 *
 * @param config Pointer to radio configuration structure to fill
 * @return 0 on success, negative value on error
 */
int radio_get_config(radio_config_t *config)
{
    if (!config)
    {
        return -1;
    }

    /* Return the cached configuration */
    *config = radio_state.config;

    return 0;
}

/**
 * Set the radio to receive mode
 *
 * This function configures the radio for continuous or timed reception
 * of LoRa packets. When a packet is received, the registered rx_callback
 * will be invoked.
 *
 * @param timeout Timeout in milliseconds (0 for continuous reception)
 * @return 0 on success, negative value on error
 */
int radio_set_rx(uint32_t timeout)
{
    /* Check state */
    if (radio_state.state == RADIO_STATE_RX)
    {
        return 0; /* Already in RX mode */
    }

    /* Set the radio to standby mode first */
    uint8_t standby_cmd = 0x00; /* RC oscillator */
    radio_send_command(RADIO_CMD_SET_STANDBY, &standby_cmd, 1);

    /* Wait for radio to be ready */
    while (platform_gpio_read(RADIO_BUSY_PIN))
    {
        platform_delay_ms(1);
    }

    /* Clear IRQ status */
    uint8_t clear_irq[2] = {0xFF, 0xFF}; /* Clear all IRQs */
    radio_send_command(RADIO_CMD_CLEAR_IRQ_STATUS, clear_irq, 2);

    /* Prepare and send RX command */
    uint8_t rx_cmd[3];
    if (timeout == 0)
    {
        /* Continuous mode */
        rx_cmd[0] = 0xFF;
        rx_cmd[1] = 0xFF;
        rx_cmd[2] = 0xFF;
    }
    else
    {
        /* Timed mode - convert to SX126x ticks (15.625us per tick) */
        uint32_t ticks = (timeout * 1000) / 15625;
        rx_cmd[0] = (ticks >> 16) & 0xFF;
        rx_cmd[1] = (ticks >> 8) & 0xFF;
        rx_cmd[2] = ticks & 0xFF;
    }

    /* Send RX command */
    radio_send_command(RADIO_CMD_SET_RX, rx_cmd, 3);

    /* Update state */
    radio_state.state = RADIO_STATE_RX;

    return 0;
}

/**
 * Transmit a packet
 *
 * This function transmits a LoRa packet with the specified data.
 * When transmission is complete, the registered tx_callback will be invoked.
 *
 * @param data Pointer to packet data to transmit
 * @param size Size of packet data in bytes
 * @param timeout Timeout in milliseconds (0 for default timeout)
 * @return 0 on success, negative value on error
 */
int radio_transmit(const uint8_t *data, size_t size, uint32_t timeout)
{
    if (!data || size == 0 || size > RADIO_MAX_BUFFER_SIZE)
    {
        return -1;
    }

    /* Set the radio to standby mode first */
    uint8_t standby_cmd = 0x00; /* RC oscillator */
    radio_send_command(RADIO_CMD_SET_STANDBY, &standby_cmd, 1);

    /* Wait for radio to be ready */
    while (platform_gpio_read(RADIO_BUSY_PIN))
    {
        platform_delay_ms(1);
    }

    /* Clear IRQ status */
    uint8_t clear_irq[2] = {0xFF, 0xFF}; /* Clear all IRQs */
    radio_send_command(RADIO_CMD_CLEAR_IRQ_STATUS, clear_irq, 2);

    /* Write data to buffer */
    radio_send_command(RADIO_CMD_WRITE_BUFFER, (uint8_t *)data, size);

    /* Prepare TX command */
    uint8_t tx_cmd[3];
    if (timeout == 0)
    {
        /* Default timeout - 2 seconds */
        uint32_t ticks = (2000 * 1000) / 15625; /* Convert to SX126x ticks */
        tx_cmd[0] = (ticks >> 16) & 0xFF;
        tx_cmd[1] = (ticks >> 8) & 0xFF;
        tx_cmd[2] = ticks & 0xFF;
    }
    else
    {
        /* Convert to SX126x ticks (15.625us per tick) */
        uint32_t ticks = (timeout * 1000) / 15625;
        tx_cmd[0] = (ticks >> 16) & 0xFF;
        tx_cmd[1] = (ticks >> 8) & 0xFF;
        tx_cmd[2] = ticks & 0xFF;
    }

    /* Send TX command */
    radio_send_command(RADIO_CMD_SET_TX, tx_cmd, 3);

    /* Update state and counters */
    radio_state.state = RADIO_STATE_TX;
    radio_state.tx_count++;

    return 0;
}

/**
 * Set radio to idle state
 *
 * This function sets the radio to standby mode (idle state), which
 * reduces power consumption while keeping the radio responsive to commands.
 *
 * @return 0 on success, negative value on error
 */
int radio_set_idle(void)
{
    /* Send standby command */
    uint8_t standby_cmd = 0x00; /* RC oscillator */
    radio_send_command(RADIO_CMD_SET_STANDBY, &standby_cmd, 1);

    /* Wait for radio to be ready */
    while (platform_gpio_read(RADIO_BUSY_PIN))
    {
        platform_delay_ms(1);
    }

    /* Update state */
    radio_state.state = RADIO_STATE_IDLE;

    return 0;
}

/**
 * Perform channel activity detection
 *
 * This function performs a Channel Activity Detection (CAD) operation to
 * determine if the current channel is occupied by a LoRa transmission.
 *
 * @return 1 if channel is active, 0 if channel is clear, negative value on error
 */
int radio_check_channel(void)
{
    /* Set the radio to standby mode first */
    radio_set_idle();

    /* Wait for radio to be ready */
    while (platform_gpio_read(RADIO_BUSY_PIN))
    {
        platform_delay_ms(1);
    }

    /* Clear IRQ status */
    uint8_t clear_irq[2] = {0xFF, 0xFF}; /* Clear all IRQs */
    radio_send_command(RADIO_CMD_CLEAR_IRQ_STATUS, clear_irq, 2);

    /* Configure CAD parameters */
    uint8_t cad_params[7];
    cad_params[0] = 0x01; /* Number of symbols (1-16) */
    cad_params[1] = 0x20; /* Detection peak */
    cad_params[2] = 0x0A; /* Detection min */
    cad_params[3] = 0x00; /* Reserved */
    cad_params[4] = 0x00; /* Reserved */
    cad_params[5] = 0x00; /* Reserved */
    cad_params[6] = 0x00; /* Exit mode (after CAD, go to standby) */

    radio_send_command(RADIO_CMD_SET_CAD_PARAMS, cad_params, 7);

    /* Start CAD */
    radio_send_command(RADIO_CMD_SET_CAD, NULL, 0);

    /* Update state */
    radio_state.state = RADIO_STATE_CAD;

    /* Wait for CAD to complete or timeout */
    uint32_t start_time = platform_get_time_ms();
    uint8_t cad_done = 0;
    uint8_t cad_detected = 0;

    while ((platform_get_time_ms() - start_time) < 200)
    { /* 200ms timeout */
        /* Check IRQ status */
        uint8_t irq_status[2] = {0, 0};
        radio_send_command(RADIO_CMD_GET_IRQ_STATUS, NULL, 0);
        
        /* Read the IRQ status from the radio */
        if (radio_wait_on_busy() == 0) {
            platform_gpio_write(RADIO_NSS_PIN, 0);
            
            /* SPI read requires a NOP byte */
            uint8_t nop = 0;
            platform_spi_transfer(RADIO_SPI_INTERFACE, &nop, &irq_status[0], 1);
            platform_spi_transfer(RADIO_SPI_INTERFACE, &nop, &irq_status[1], 1);
            
            platform_gpio_write(RADIO_NSS_PIN, 1);
        }

        uint16_t irq = (irq_status[1] << 8) | irq_status[0];

        if (irq & RADIO_IRQ_CAD_DONE)
        {
            cad_done = 1;
            if (irq & RADIO_IRQ_CAD_DETECTED)
            {
                cad_detected = 1;
            }
            break;
        }

        platform_delay_ms(1);
    }

    /* Return to idle state */
    radio_set_idle();

    if (!cad_done)
    {
        return -1; /* Timeout */
    }

    return cad_detected ? 1 : 0;
}

/**
 * Register a callback for received packets
 *
 * This function registers a callback function that will be invoked when
 * a packet is successfully received by the radio.
 *
 * @param callback Function to call when a packet is received
 * @return 0 on success
 */
int radio_set_rx_callback(radio_rx_callback_t callback)
{
    radio_state.rx_callback = callback;
    return 0;
}

/**
 * Register a callback for completed transmissions
 *
 * This function registers a callback function that will be invoked when
 * a packet transmission is successfully completed.
 *
 * @param callback Function to call when a transmission completes
 * @return 0 on success
 */
int radio_set_tx_callback(radio_tx_callback_t callback)
{
    radio_state.tx_callback = callback;
    return 0;
}

/**
 * Register a callback for radio errors
 *
 * This function registers a callback function that will be invoked when
 * a radio error occurs (such as CRC error, timeout, etc.).
 *
 * @param callback Function to call when an error occurs
 * @return 0 on success
 */
int radio_set_error_callback(radio_error_callback_t callback)
{
    radio_state.error_callback = callback;
    return 0;
}

/**
 * Get the current RSSI
 *
 * This function measures the current Received Signal Strength Indicator (RSSI)
 * value on the active channel. It is only valid when the radio is in RX mode.
 *
 * @return RSSI value in dBm, 0 if not in RX mode
 */
int16_t radio_get_rssi(void)
{
    if (radio_state.state != RADIO_STATE_RX)
    {
        return 0; /* Only valid in RX mode */
    }

    /* Read instantaneous RSSI */
    uint8_t rssi_val = 0;
    radio_send_command(RADIO_CMD_GET_RSSI_INST, NULL, 0);
    
    /* Read the RSSI value from the radio */
    if (radio_wait_on_busy() == 0) {
        platform_gpio_write(RADIO_NSS_PIN, 0);
        
        /* SPI read requires a NOP byte */
        uint8_t nop = 0;
        platform_spi_transfer(RADIO_SPI_INTERFACE, &nop, &rssi_val, 1);
        
        platform_gpio_write(RADIO_NSS_PIN, 1);
    }

    /* Convert to dBm (SX126x specific conversion) */
    int16_t rssi_dbm = -rssi_val / 2;

    /* Cache the value */
    radio_state.last_rssi = rssi_dbm;

    return rssi_dbm;
}

/**
 * Get the last packet's SNR
 *
 * This function returns the Signal-to-Noise Ratio (SNR) of the last
 * received packet. It is updated after each successful packet reception.
 *
 * @return SNR value in dB
 */
int8_t radio_get_snr(void)
{
    /* Return the last measured SNR */
    return radio_state.last_snr;
}

/**
 * Measure the noise floor on the current frequency
 *
 * This function measures the ambient noise level (noise floor) on the
 * current frequency by taking multiple RSSI samples and averaging them.
 *
 * @return Noise floor level in dBm
 */
int16_t radio_measure_noise_floor(void)
{
    const int num_samples = 10;
    int16_t rssi_sum = 0;
    int valid_samples = 0;

    /* Save current state */
    uint8_t prev_state = radio_state.state;

    /* Switch to RX mode */
    radio_set_rx(0);

    /* Wait for radio to stabilize */
    platform_delay_ms(10);

    /* Sample RSSI multiple times */
    for (int i = 0; i < num_samples; i++)
    {
        int16_t rssi = radio_get_rssi();
        if (rssi < 0)
        { /* Valid RSSI readings are negative */
            rssi_sum += rssi;
            valid_samples++;
        }
        platform_delay_ms(10);
    }

    /* Restore previous state */
    if (prev_state == RADIO_STATE_IDLE)
    {
        radio_set_idle();
    }

    /* Calculate average */
    if (valid_samples > 0)
    {
        return rssi_sum / valid_samples;
    }
    else
    {
        return -120; /* Default noise floor if no valid readings */
    }
}

/**
 * Switch the radio to a different band
 *
 * This function reconfigures the radio to operate on a different frequency band
 * while preserving other modulation parameters. Supported bands are 433MHz,
 * 868MHz, and 915MHz.
 *
 * @param band Band identifier (BAND_433MHZ, BAND_868MHZ, or BAND_915MHZ)
 * @return 0 on success, negative value on error
 */
int radio_switch_band(uint8_t band)
{
    /* Get appropriate band configuration */
    radio_config_t new_config;

    switch (band)
    {
    case BAND_433MHZ:
        new_config = BAND_CONFIG_433MHZ;
        break;
    case BAND_868MHZ:
        new_config = BAND_CONFIG_868MHZ;
        break;
    case BAND_915MHZ:
        new_config = BAND_CONFIG_915MHZ;
        break;
    default:
        return -1;
    }

    /* Preserve current parameters that are not band-specific */
    new_config.spreadFactor = radio_state.config.spreadFactor;
    new_config.codingRate = radio_state.config.codingRate;
    new_config.bandwidth = radio_state.config.bandwidth;
    new_config.preambleLength = radio_state.config.preambleLength;

    /* Apply the new configuration */
    return radio_set_config(&new_config);
}

/**
 * Get the current state of the radio
 *
 * This function returns the current operational state of the radio
 * (IDLE, RX, TX, or CAD).
 *
 * @return Radio state (RADIO_STATE_XXX constant)
 */
uint8_t radio_get_state(void)
{
    return radio_state.state;
}

/**
 * Get radio statistics
 *
 * This function retrieves various statistics about radio operation including
 * the number of packets sent, received, and errors encountered.
 *
 * @param packets_sent Pointer to store the number of transmitted packets (can be NULL)
 * @param packets_received Pointer to store the number of received packets (can be NULL)
 * @param rx_errors Pointer to store the number of reception errors (can be NULL)
 * @return 0 on success
 */
int radio_get_stats(uint32_t *packets_sent, uint32_t *packets_received, uint32_t *rx_errors)
{
    if (packets_sent)
    {
        *packets_sent = radio_state.tx_count;
    }

    if (packets_received)
    {
        *packets_received = radio_state.rx_count;
    }

    if (rx_errors)
    {
        *rx_errors = radio_state.error_count;
    }

    return 0;
}

/**
 * Perform a scan of the specified frequency band
 *
 * This function scans an entire frequency band, measuring the noise/signal
 * level at each channel and storing the RSSI values in the provided array.
 *
 * @param band Band identifier (BAND_433MHZ, BAND_868MHZ, or BAND_915MHZ)
 * @param rssi_values Array to store RSSI values for each channel
 * @param num_channels Number of channels to scan
 * @return Number of channels scanned on success, negative value on error
 */
int radio_scan_band(uint8_t band, int16_t *rssi_values, size_t num_channels)
{
    if (!rssi_values || num_channels == 0)
    {
        return -1;
    }

    /* Get base frequency for the band */
    uint32_t base_freq = 0;
    uint32_t step = 0;

    switch (band)
    {
    case BAND_433MHZ:
        base_freq = 430000000; /* Start at 430 MHz */
        step = 500000;         /* 500 kHz steps */
        break;
    case BAND_868MHZ:
        base_freq = 863000000; /* Start at 863 MHz */
        step = 1000000;        /* 1 MHz steps */
        break;
    case BAND_915MHZ:
        base_freq = 902000000; /* Start at 902 MHz */
        step = 1000000;        /* 1 MHz steps */
        break;
    default:
        return -2;
    }

    /* Save current configuration */
    radio_config_t original_config = radio_state.config;

    /* Create a temporary configuration for scanning */
    radio_config_t scan_config = original_config;
    scan_config.bandwidth = 250;  /* Use wider bandwidth for scanning */
    scan_config.spreadFactor = 7; /* Use smallest spreading factor for speed */

    /* Scan each channel */
    for (size_t i = 0; i < num_channels; i++)
    {
        /* Set frequency for this channel */
        scan_config.frequency = base_freq + (i * step);

        /* Apply config for this channel */
        radio_set_config(&scan_config);

        /* Measure noise floor */
        rssi_values[i] = radio_measure_noise_floor();
    }

    /* Restore original configuration */
    radio_set_config(&original_config);

    return num_channels;
}

/**
 * Process received data into a packet structure
 *
 * This function takes raw received data from the radio and deserializes it
 * into a packet structure for higher-level processing. It uses the packet
 * module's deserialization function.
 *
 * @param data Pointer to the raw packet data
 * @param len Length of the raw packet data in bytes
 * @param packet Pointer to the packet structure to fill
 * @return 0 on success, negative value on error
 */
int radio_process_rx(const uint8_t *data, size_t len, packet_t *packet)
{
    if (!data || !packet || len < sizeof(packet_header_t))
    {
        return -1;
    }

    /* Use packet deserialization function */
    return packet_deserialize(data, len, packet);
}

/* Internal helper functions */

/**
 * Set LoRa modulation parameters
 *
 * This internal function configures the SX126x radio with the appropriate
 * LoRa modulation parameters including spreading factor, bandwidth, coding rate,
 * and low data rate optimization settings based on the current configuration.
 *
 * @return 0 on success, negative value on error
 */
static int radio_set_lora_modulation(void)
{
    uint8_t mod_params[4];

    /* Configure modulation parameters */
    mod_params[0] = radio_state.config.spreadFactor; /* Spreading factor (7-12) */

    /* Bandwidth mapping for SX126x */
    switch (radio_state.config.bandwidth)
    {
    case 7:
        mod_params[1] = RADIO_BANDWIDTH_7;
        break;
    case 10:
        mod_params[1] = RADIO_BANDWIDTH_10;
        break;
    case 15:
        mod_params[1] = RADIO_BANDWIDTH_15;
        break;
    case 20:
        mod_params[1] = RADIO_BANDWIDTH_20;
        break;
    case 31:
        mod_params[1] = RADIO_BANDWIDTH_31;
        break;
    case 41:
        mod_params[1] = RADIO_BANDWIDTH_41;
        break;
    case 62:
        mod_params[1] = RADIO_BANDWIDTH_62;
        break;
    case 125:
        mod_params[1] = RADIO_BANDWIDTH_125;
        break;
    case 250:
        mod_params[1] = RADIO_BANDWIDTH_250;
        break;
    case 500:
        mod_params[1] = RADIO_BANDWIDTH_500;
        break;
    default:
        mod_params[1] = RADIO_BANDWIDTH_125; /* Default to 125 kHz */
        break;
    }

    /* Coding rate */
    switch (radio_state.config.codingRate)
    {
    case 5:
        mod_params[2] = RADIO_CODING_RATE_4_5;
        break;
    case 6:
        mod_params[2] = RADIO_CODING_RATE_4_6;
        break;
    case 7:
        mod_params[2] = RADIO_CODING_RATE_4_7;
        break;
    case 8:
        mod_params[2] = RADIO_CODING_RATE_4_8;
        break;
    default:
        mod_params[2] = RADIO_CODING_RATE_4_5; /* Default to 4/5 */
        break;
    }

    /* Low data rate optimization */
    mod_params[3] = (radio_state.config.spreadFactor > 10) ? 0x01 : 0x00;

    return radio_send_command(RADIO_CMD_SET_MODULATION_PARAMS, mod_params, 4);
}

/**
 * Set LoRa packet parameters
 *
 * This internal function configures the SX126x radio with the appropriate
 * LoRa packet parameters including preamble length, variable length mode,
 * maximum payload size, CRC mode, and IQ settings.
 *
 * @return 0 on success, negative value on error
 */
static int radio_set_lora_packet_params(void)
{
    uint8_t packet_params[6];

    /* Configure packet parameters */
    packet_params[0] = (radio_state.config.preambleLength >> 8) & 0xFF; /* Preamble length MSB */
    packet_params[1] = radio_state.config.preambleLength & 0xFF;        /* Preamble length LSB */
    packet_params[2] = 0x00;                                            /* Variable length packets */
    packet_params[3] = 0xFF;                                            /* Maximum payload length */
    packet_params[4] = 0x01;                                            /* CRC enabled */
    packet_params[5] = 0x00;                                            /* Standard IQ mode */

    return radio_send_command(RADIO_CMD_SET_PACKET_PARAMS, packet_params, 6);
}

/**
 * Wait for the BUSY pin to go low, indicating the radio is ready
 */
static int radio_wait_on_busy(void)
{
    uint32_t start_time = platform_get_time_ms();

    while (platform_gpio_read(RADIO_BUSY_PIN))
    {
        if (platform_get_time_ms() - start_time > 100)
        {
            return -1; /* Timeout */
        }
        platform_delay_ms(1);
    }

    return 0;
}

/**
 * Write to a radio register
 */
static int radio_write_register(uint16_t addr, uint8_t *data, size_t len)
{
    if (radio_wait_on_busy() != 0)
    {
        return -1;
    }

    /* Set NSS low to start SPI transaction */
    platform_gpio_write(RADIO_NSS_PIN, 0);

    /* Send write register command */
    uint8_t cmd_buf[3];
    cmd_buf[0] = RADIO_CMD_WRITE_REGISTER;
    cmd_buf[1] = (addr >> 8) & 0xFF;
    cmd_buf[2] = addr & 0xFF;

    platform_spi_transfer(RADIO_SPI_INTERFACE, cmd_buf, NULL, 3);

    /* Send data */
    platform_spi_transfer(RADIO_SPI_INTERFACE, data, NULL, len);

    /* Set NSS high to end SPI transaction */
    platform_gpio_write(RADIO_NSS_PIN, 1);

    return 0;
}

/**
 * Read from a radio register
 */
static int radio_read_register(uint16_t addr, uint8_t *data, size_t len)
{
    if (radio_wait_on_busy() != 0)
    {
        return -1;
    }

    /* Set NSS low to start SPI transaction */
    platform_gpio_write(RADIO_NSS_PIN, 0);

    /* Send read register command */
    uint8_t cmd_buf[4];
    cmd_buf[0] = RADIO_CMD_READ_REGISTER;
    cmd_buf[1] = (addr >> 8) & 0xFF;
    cmd_buf[2] = addr & 0xFF;
    cmd_buf[3] = 0; /* NOP byte */

    platform_spi_transfer(RADIO_SPI_INTERFACE, cmd_buf, NULL, 4);

    /* Read data */
    uint8_t *rx_buf = (uint8_t *)malloc(len);
    if (!rx_buf)
    {
        platform_gpio_write(RADIO_NSS_PIN, 1);
        return -2;
    }

    memset(rx_buf, 0, len);
    platform_spi_transfer(RADIO_SPI_INTERFACE, rx_buf, data, len);

    free(rx_buf);

    /* Set NSS high to end SPI transaction */
    platform_gpio_write(RADIO_NSS_PIN, 1);

    return 0;
}

/**
 * Send a command to the radio
 */
static int radio_send_command(uint8_t cmd, uint8_t *data, size_t len)
{
    if (radio_wait_on_busy() != 0)
    {
        return -1;
    }

    /* Set NSS low to start SPI transaction */
    platform_gpio_write(RADIO_NSS_PIN, 0);

    /* Send command */
    platform_spi_transfer(RADIO_SPI_INTERFACE, &cmd, NULL, 1);

    /* Send data if any */
    if (data && len > 0)
    {
        platform_spi_transfer(RADIO_SPI_INTERFACE, data, NULL, len);
    }

    /* Set NSS high to end SPI transaction */
    platform_gpio_write(RADIO_NSS_PIN, 1);

    return 0;
}

/**
 * Read a received packet from the radio
 */
static int radio_read_packet(uint8_t *buffer, size_t *size, int16_t *rssi, int8_t *snr)
{
    /* Get buffer status */
    uint8_t buf_status[2] = {0, 0};
    radio_send_command(RADIO_CMD_GET_RX_BUFFER_STATUS, NULL, 0);
    
    /* Read the buffer status from the radio */
    if (radio_wait_on_busy() == 0) {
        platform_gpio_write(RADIO_NSS_PIN, 0);
        
        /* SPI read requires a NOP byte */
        uint8_t nop = 0;
        platform_spi_transfer(RADIO_SPI_INTERFACE, &nop, &buf_status[0], 1);
        platform_spi_transfer(RADIO_SPI_INTERFACE, &nop, &buf_status[1], 1);
        
        platform_gpio_write(RADIO_NSS_PIN, 1);
    }

    uint8_t payload_len = buf_status[0];
    uint8_t rx_start_ptr = buf_status[1];

    /* Read payload */
    if (payload_len > 0)
    {
        /* Set NSS low to start SPI transaction */
        platform_gpio_write(RADIO_NSS_PIN, 0);

        /* Send read buffer command */
        uint8_t cmd_buf[2];
        cmd_buf[0] = RADIO_CMD_READ_BUFFER;
        cmd_buf[1] = rx_start_ptr;

        platform_spi_transfer(RADIO_SPI_INTERFACE, cmd_buf, NULL, 2);

        /* Read data */
        uint8_t *rx_buf = (uint8_t *)malloc(payload_len);
        if (!rx_buf)
        {
            platform_gpio_write(RADIO_NSS_PIN, 1);
            return -1;
        }

        memset(rx_buf, 0, payload_len);
        platform_spi_transfer(RADIO_SPI_INTERFACE, rx_buf, buffer, payload_len);

        free(rx_buf);

        /* Set NSS high to end SPI transaction */
        platform_gpio_write(RADIO_NSS_PIN, 1);

        /* Get packet status */
        uint8_t pkt_status[3] = {0, 0, 0};
        radio_send_command(RADIO_CMD_GET_PACKET_STATUS, NULL, 0);
        
        /* Read the packet status from the radio */
        if (radio_wait_on_busy() == 0) {
            platform_gpio_write(RADIO_NSS_PIN, 0);
            
            /* SPI read requires a NOP byte */
            uint8_t nop = 0;
            platform_spi_transfer(RADIO_SPI_INTERFACE, &nop, &pkt_status[0], 1);
            platform_spi_transfer(RADIO_SPI_INTERFACE, &nop, &pkt_status[1], 1);
            platform_spi_transfer(RADIO_SPI_INTERFACE, &nop, &pkt_status[2], 1);
            
            platform_gpio_write(RADIO_NSS_PIN, 1);
        }

        /* Extract RSSI and SNR */
        *rssi = -pkt_status[0] / 2;       /* Convert to dBm (SX126x specific conversion) */
        *snr = (int8_t)pkt_status[1] / 4; /* Convert to dB (SX126x specific conversion) */

        /* Cache the values */
        radio_state.last_rssi = *rssi;
        radio_state.last_snr = *snr;

        /* Set packet size */
        *size = payload_len;

        return 0;
    }

    return -1;
}

/**
 * Handle radio interrupts
 *
 * This function is called when the DIO1 pin signals an interrupt from the radio.
 * It reads the interrupt status, processes any received packets, handles transmit
 * completion, and manages error conditions by invoking the appropriate callbacks.
 *
 * @param arg Unused argument (required by interrupt handler signature)
 */
static void radio_handle_interrupt(void *arg)
{
    /* Get IRQ status */
    uint8_t irq_status[2] = {0, 0};
    radio_send_command(RADIO_CMD_GET_IRQ_STATUS, NULL, 0);
    
    /* Read the IRQ status from the radio */
    if (radio_wait_on_busy() == 0) {
        platform_gpio_write(RADIO_NSS_PIN, 0);
        
        /* SPI read requires a NOP byte */
        uint8_t nop = 0;
        platform_spi_transfer(RADIO_SPI_INTERFACE, &nop, &irq_status[0], 1);
        platform_spi_transfer(RADIO_SPI_INTERFACE, &nop, &irq_status[1], 1);
        
        platform_gpio_write(RADIO_NSS_PIN, 1);
    }

    uint16_t irq = (irq_status[1] << 8) | irq_status[0];

    /* Clear IRQ status */
    uint8_t clear_irq[2] = {0xFF, 0xFF}; /* Clear all IRQs */
    radio_send_command(RADIO_CMD_CLEAR_IRQ_STATUS, clear_irq, 2);

    /* Process transmit done */
    if (irq & RADIO_IRQ_TX_DONE)
    {
        /* Update state */
        radio_state.state = RADIO_STATE_IDLE;

        /* Call callback if registered */
        if (radio_state.tx_callback)
        {
            radio_state.tx_callback();
        }
    }

    /* Process receive done */
    if (irq & RADIO_IRQ_RX_DONE)
    {
        /* Check for CRC error */
        if (irq & RADIO_IRQ_CRC_ERROR)
        {
            radio_state.error_count++;

            /* Call error callback if registered */
            if (radio_state.error_callback)
            {
                radio_state.error_callback(irq);
            }
        }
        else
        {
            /* Valid packet received */
            uint8_t buffer[RADIO_MAX_BUFFER_SIZE];
            size_t size = 0;
            int16_t rssi = 0;
            int8_t snr = 0;

            /* Read the packet */
            if (radio_read_packet(buffer, &size, &rssi, &snr) == 0)
            {
                radio_state.rx_count++;

                /* Call callback if registered */
                if (radio_state.rx_callback)
                {
                    radio_state.rx_callback(buffer, size, rssi, snr);
                }
            }
        }

        /* Go back to standby mode */
        radio_state.state = RADIO_STATE_IDLE;
    }

    /* Process timeouts */
    if (irq & RADIO_IRQ_TIMEOUT)
    {
        radio_state.error_count++;

        /* Call error callback if registered */
        if (radio_state.error_callback)
        {
            radio_state.error_callback(irq);
        }

        /* Go back to standby mode */
        radio_state.state = RADIO_STATE_IDLE;
    }

    /* Process CAD completion */
    if (irq & RADIO_IRQ_CAD_DONE)
    {
        /* Go back to standby mode */
        radio_state.state = RADIO_STATE_IDLE;
    }
}