#ifndef AUDIO_H
#define AUDIO_H

#include <stdint.h>
#include <stddef.h>

/**
 * @file audio.h
 * @brief Audio processing and codec functionality
 */

/* Codec2 modes */
#define CODEC2_MODE_3200       0   /* 3200 bits/s, 160 samples -> 8 bytes */
#define CODEC2_MODE_2400       1   /* 2400 bits/s, 160 samples -> 6 bytes */
#define CODEC2_MODE_1600       2   /* 1600 bits/s, 320 samples -> 8 bytes */
#define CODEC2_MODE_1300       3   /* 1300 bits/s, 320 samples -> 7 bytes */
#define CODEC2_MODE_700C       4   /* 700 bits/s, 320 samples -> 4 bytes */

/* Audio configuration */
#define AUDIO_SAMPLE_RATE     8000 /* Sample rate in Hz */
#define AUDIO_FRAME_SIZE      160  /* Audio frame size in samples (20ms @ 8kHz) */
#define MAX_FRAMES_PER_PACKET  10  /* Maximum number of codec frames per packet */

/* Audio states */
#define AUDIO_STATE_IDLE       0   /* Not capturing or playing audio */
#define AUDIO_STATE_CAPTURING  1   /* Capturing audio (mic active) */
#define AUDIO_STATE_PLAYING    2   /* Playing received audio */
#define AUDIO_STATE_BOTH       3   /* Both capturing and playing (full duplex) */

/* PTT (Push-to-Talk) states */
#define PTT_RELEASED           0   /* PTT button released (receive mode) */
#define PTT_PRESSED            1   /* PTT button pressed (transmit mode) */

/**
 * Initialize the audio subsystem
 * 
 * @param codec_mode Codec2 mode to use
 * @return 0 on success, negative on error
 */
int audio_init(uint8_t codec_mode);

/**
 * Start audio capture from microphone
 * 
 * @return 0 on success, negative on error
 */
int audio_start_capture(void);

/**
 * Stop audio capture
 * 
 * @return 0 on success, negative on error
 */
int audio_stop_capture(void);

/**
 * Start audio playback to speaker
 * 
 * @return 0 on success, negative on error
 */
int audio_start_playback(void);

/**
 * Stop audio playback
 * 
 * @return 0 on success, negative on error
 */
int audio_stop_playback(void);

/**
 * Process push-to-talk button state
 * 
 * @param ptt_state Current state of PTT button
 * @return 0 on success, negative on error
 */
int audio_process_ptt(uint8_t ptt_state);

/**
 * Process a captured audio buffer
 * 
 * @param pcm_buffer Buffer containing raw PCM samples
 * @param samples Number of samples in buffer
 * @return 0 on success, negative on error
 */
int audio_process_captured(const int16_t* pcm_buffer, size_t samples);

/**
 * Encode an audio frame using Codec2
 * 
 * @param pcm_samples Buffer containing raw PCM samples
 * @param coded_bits Buffer to store encoded bits
 * @return Size of encoded data in bytes, or negative on error
 */
int audio_encode_frame(const int16_t* pcm_samples, uint8_t* coded_bits);

/**
 * Decode a Codec2 frame to PCM audio
 * 
 * @param coded_bits Buffer containing encoded bits
 * @param pcm_samples Buffer to store decoded PCM samples
 * @return Number of decoded samples, or negative on error
 */
int audio_decode_frame(const uint8_t* coded_bits, int16_t* pcm_samples);

/**
 * Queue an encoded audio frame for transmission
 * 
 * @param coded_bits Buffer containing encoded bits
 * @param size Size of encoded data in bytes
 * @return 0 on success, negative on error
 */
int audio_queue_for_tx(const uint8_t* coded_bits, size_t size);

/**
 * Queue received audio data for playback
 * 
 * @param coded_bits Buffer containing encoded bits
 * @param size Size of encoded data in bytes
 * @return 0 on success, negative on error
 */
int audio_queue_for_playback(const uint8_t* coded_bits, size_t size);

/**
 * Get the next audio packet for transmission
 * 
 * @param packet_buffer Buffer to store the packet
 * @param max_size Maximum size of buffer in bytes
 * @return Size of packet in bytes, 0 if no packet available, negative on error
 */
int audio_get_next_packet(uint8_t* packet_buffer, size_t max_size);

#endif /* AUDIO_H */