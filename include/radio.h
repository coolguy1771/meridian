#ifndef RADIO_H
#define RADIO_H

#include <stdint.h>
#include <stddef.h>
#include "radio_config.h"

/**
 * @file radio.h
 * @brief Low-level radio interface for SX126x LoRa transceivers
 */

/* Radio states */
#define RADIO_STATE_IDLE       0   /* Radio is idle */
#define RADIO_STATE_RX         1   /* Radio is in receive mode */
#define RADIO_STATE_TX         2   /* Radio is transmitting */
#define RADIO_STATE_CAD        3   /* Radio is in channel activity detection */
#define RADIO_STATE_ERROR      4   /* Radio is in error state */

/* IRQ flags */
#define IRQ_TX_DONE            (1 << 0)  /* Transmission completed */
#define IRQ_RX_DONE            (1 << 1)  /* Reception completed */
#define IRQ_PREAMBLE_DETECTED  (1 << 2)  /* Preamble detected */
#define IRQ_SYNC_WORD_VALID    (1 << 3)  /* Valid sync word detected */
#define IRQ_HEADER_VALID       (1 << 4)  /* Valid header detected */
#define IRQ_HEADER_ERROR       (1 << 5)  /* Header error */
#define IRQ_CRC_ERROR          (1 << 6)  /* CRC error */
#define IRQ_CAD_DONE           (1 << 7)  /* Channel activity detection complete */
#define IRQ_CAD_DETECTED       (1 << 8)  /* Channel activity detected */
#define IRQ_TIMEOUT            (1 << 9)  /* RX or TX timeout */

/* Callback types */
typedef void (*radio_rx_callback_t)(uint8_t* buffer, size_t size, int16_t rssi, int8_t snr);
typedef void (*radio_tx_callback_t)(void);
typedef void (*radio_error_callback_t)(uint16_t irq_status);

/**
 * Initialize the radio hardware
 * 
 * @param config Initial radio configuration
 * @return 0 on success, negative on error
 */
int radio_init(const radio_config_t* config);

/**
 * Set the radio configuration
 * 
 * @param config New radio configuration
 * @return 0 on success, negative on error
 */
int radio_set_config(const radio_config_t* config);

/**
 * Get the current radio configuration
 * 
 * @param config Pointer to configuration structure to fill
 * @return 0 on success, negative on error
 */
int radio_get_config(radio_config_t* config);

/**
 * Set the radio to receive mode
 * 
 * @param timeout Timeout in milliseconds (0 for continuous)
 * @return 0 on success, negative on error
 */
int radio_set_rx(uint32_t timeout);

/**
 * Transmit a packet
 * 
 * @param data Packet data to transmit
 * @param size Size of packet in bytes
 * @param timeout Timeout in milliseconds (0 for default)
 * @return 0 on success, negative on error
 */
int radio_transmit(const uint8_t* data, size_t size, uint32_t timeout);

/**
 * Set radio to idle state
 * 
 * @return 0 on success, negative on error
 */
int radio_set_idle(void);

/**
 * Perform channel activity detection
 * 
 * @return 1 if channel is busy, 0 if clear, negative on error
 */
int radio_check_channel(void);

/**
 * Register a callback for received packets
 * 
 * @param callback Function to call when a packet is received
 * @return 0 on success, negative on error
 */
int radio_set_rx_callback(radio_rx_callback_t callback);

/**
 * Register a callback for completed transmissions
 * 
 * @param callback Function to call when transmission completes
 * @return 0 on success, negative on error
 */
int radio_set_tx_callback(radio_tx_callback_t callback);

/**
 * Register a callback for radio errors
 * 
 * @param callback Function to call when an error occurs
 * @return 0 on success, negative on error
 */
int radio_set_error_callback(radio_error_callback_t callback);

/**
 * Get the current RSSI (Received Signal Strength Indicator)
 * 
 * @return RSSI in dBm, or 0 if not in receive mode
 */
int16_t radio_get_rssi(void);

/**
 * Get the last packet's SNR (Signal to Noise Ratio)
 * 
 * @return SNR in dB, or 0 if no packet received
 */
int8_t radio_get_snr(void);

/**
 * Measure the noise floor on the current frequency
 * 
 * @return Noise floor in dBm, or 0 if measurement failed
 */
int16_t radio_measure_noise_floor(void);

/**
 * Switch the radio to a different band
 * 
 * @param band The band to switch to (BAND_433MHZ, BAND_868MHZ, BAND_915MHZ)
 * @return 0 on success, negative on error
 */
int radio_switch_band(uint8_t band);

/**
 * Get the current state of the radio
 * 
 * @return Radio state (RADIO_STATE_*)
 */
uint8_t radio_get_state(void);

#endif /* RADIO_H */