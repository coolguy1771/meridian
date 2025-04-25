#include "audio.h"
#include "platform.h"
#include <string.h>
#include <stdlib.h>
#include <math.h>

/* Define M_PI if not already defined */
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#ifdef USE_CODEC2
#include <codec2/codec2.h>
#endif

/* Defines for the Codec2 frame sizes */
static const size_t CODEC2_FRAME_SIZES[] = {
    8,  /* CODEC2_MODE_3200 - 160 samples -> 8 bytes */
    6,  /* CODEC2_MODE_2400 - 160 samples -> 6 bytes */
    8,  /* CODEC2_MODE_1600 - 320 samples -> 8 bytes */
    7,  /* CODEC2_MODE_1300 - 320 samples -> 7 bytes */
    4   /* CODEC2_MODE_700C - 320 samples -> 4 bytes */
};

static const size_t CODEC2_SAMPLE_COUNTS[] = {
    160, /* CODEC2_MODE_3200 - 20ms @ 8kHz */
    160, /* CODEC2_MODE_2400 - 20ms @ 8kHz */
    320, /* CODEC2_MODE_1600 - 40ms @ 8kHz */
    320, /* CODEC2_MODE_1300 - 40ms @ 8kHz */
    320  /* CODEC2_MODE_700C - 40ms @ 8kHz */
};

/* TX and RX queue structures */
#define TX_QUEUE_SIZE 20
#define RX_QUEUE_SIZE 20

typedef struct {
    uint8_t data[MAX_FRAMES_PER_PACKET * 8]; /* Largest possible encoded frame is 8 bytes */
    size_t size;
} audio_frame_t;

/* Module state */
static struct {
    uint8_t state;               /* Current audio state */
    uint8_t ptt_state;           /* Current PTT state */
    uint8_t codec_mode;          /* Codec2 mode in use */
    size_t coded_frame_size;     /* Size of encoded frame in bytes */
    size_t samples_per_frame;    /* Samples per codec frame */
    
#ifdef USE_CODEC2
    struct CODEC2 *codec2;       /* Codec2 instance */
#endif
    
    /* Audio hardware settings */
    uint32_t mic_gain;           /* Microphone gain (0-100) */
    uint32_t speaker_volume;     /* Speaker volume (0-100) */
    uint8_t agc_enabled;         /* Automatic gain control enabled */
    uint8_t noise_gate_enabled;  /* Noise gate enabled */
    int16_t noise_gate_threshold; /* Noise gate threshold (-32768 to 32767) */
    
    /* Audio processing settings */
    uint8_t echo_cancellation;   /* Echo cancellation enabled */
    uint8_t noise_reduction;     /* Noise reduction enabled */
    
    /* TX queue */
    audio_frame_t tx_queue[TX_QUEUE_SIZE];
    size_t tx_queue_head;
    size_t tx_queue_tail;
    size_t tx_queue_count;
    
    /* RX queue */
    audio_frame_t rx_queue[RX_QUEUE_SIZE];
    size_t rx_queue_head;
    size_t rx_queue_tail;
    size_t rx_queue_count;
    
    /* Packet assembly */
    uint8_t tx_packet_buffer[MAX_FRAMES_PER_PACKET * 8]; /* Buffer for assembling packets */
    size_t tx_packet_frames;                          /* Number of frames in current packet */
    
    /* Audio buffer for processing */
    int16_t audio_buffer[2048];
    size_t buffer_pos;
    
    /* Voice activity detection */
    uint8_t vad_enabled;
    uint16_t vad_threshold;
    uint8_t vad_hold_frames;
    uint8_t vad_active;
    uint8_t vad_hold_counter;
    
    /* Audio quality metrics */
    int8_t rx_quality;
    int8_t tx_quality;
} audio_state;

/* Forward declarations */
static void codec2_encode_frame(const int16_t* input, uint8_t* output);
static void codec2_decode_frame(const uint8_t* input, int16_t* output);
static int initialize_codec2(uint8_t mode);
static int detect_voice_activity(const int16_t* samples, size_t count);
static void apply_audio_processing(int16_t* samples, size_t count);
static int configure_audio_hardware(void);

/**
 * Initialize the audio subsystem
 */
int audio_init(uint8_t codec_mode) {
    /* Validate codec mode */
    if (codec_mode > CODEC2_MODE_700C) {
        return -1;
    }
    
    /* Initialize state */
    memset(&audio_state, 0, sizeof(audio_state));
    audio_state.codec_mode = codec_mode;
    audio_state.state = AUDIO_STATE_IDLE;
    audio_state.ptt_state = PTT_RELEASED;
    
    /* Set codec-specific parameters */
    audio_state.coded_frame_size = CODEC2_FRAME_SIZES[codec_mode];
    audio_state.samples_per_frame = CODEC2_SAMPLE_COUNTS[codec_mode];
    
    /* Initialize codec2 */
    if (initialize_codec2(codec_mode) != 0) {
        return -2;
    }
    
    /* Set default audio parameters */
    audio_state.mic_gain = 50;            /* Default 50% */
    audio_state.speaker_volume = 70;      /* Default 70% */
    audio_state.agc_enabled = 1;          /* Enable AGC by default */
    audio_state.noise_gate_enabled = 1;   /* Enable noise gate by default */
    audio_state.noise_gate_threshold = -25 * 327; /* Approx -25dB */
    
    /* Enable audio processing by default */
    audio_state.echo_cancellation = 1;
    audio_state.noise_reduction = 1;
    
    /* Configure voice activity detection */
    audio_state.vad_enabled = 1;
    audio_state.vad_threshold = 1000;     /* Default threshold */
    audio_state.vad_hold_frames = 15;     /* ~300ms hold time */
    audio_state.vad_active = 0;
    audio_state.vad_hold_counter = 0;
    
    /* Initialize audio hardware */
    if (configure_audio_hardware() != 0) {
        return -3;
    }
    
    return 0;
}

/**
 * Initialize the Codec2 voice codec
 */
static int initialize_codec2(uint8_t mode) {
#ifdef USE_CODEC2
    /* Translate our mode enum to Codec2's enum */
    int c2_mode;
    switch (mode) {
        case CODEC2_MODE_3200:
            c2_mode = CODEC2_MODE_3200;
            break;
        case CODEC2_MODE_2400:
            c2_mode = CODEC2_MODE_2400;
            break;
        case CODEC2_MODE_1600:
            c2_mode = CODEC2_MODE_1600;
            break;
        case CODEC2_MODE_1300:
            c2_mode = CODEC2_MODE_1300;
            break;
        case CODEC2_MODE_700C:
            c2_mode = CODEC2_MODE_700C;
            break;
        default:
            c2_mode = CODEC2_MODE_2400; /* Default mode */
            break;
    }
    
    /* Create the Codec2 instance */
    audio_state.codec2 = codec2_create(c2_mode);
    if (!audio_state.codec2) {
        return -1;
    }
    
    /* Get the actual bits per frame from the library */
    int bits_per_frame = codec2_bits_per_frame(audio_state.codec2);
    audio_state.coded_frame_size = (bits_per_frame + 7) / 8; /* Convert bits to bytes */
    
    /* Verify our hardcoded values match what the library says */
    int samples_per_frame = codec2_samples_per_frame(audio_state.codec2);
    if (samples_per_frame != (int)CODEC2_SAMPLE_COUNTS[mode]) {
        /* Mismatch - use the values from the library */
        audio_state.samples_per_frame = samples_per_frame;
    } else {
        audio_state.samples_per_frame = CODEC2_SAMPLE_COUNTS[mode];
    }
    
    return 0;
#else
    /* Codec2 not available - use hardcoded values */
    if (mode > CODEC2_MODE_700C) {
        mode = CODEC2_MODE_2400; /* Default to most compatible mode */
    }
    
    audio_state.coded_frame_size = CODEC2_FRAME_SIZES[mode];
    audio_state.samples_per_frame = CODEC2_SAMPLE_COUNTS[mode];
    
    return 0;
#endif
}

/**
 * Configure the audio hardware
 */
static int configure_audio_hardware(void) {
    /* In a real implementation, this would configure the audio hardware
     * including the ADC, DAC, amplifiers, etc. */
    
    /* For this implementation, we'll simulate hardware configuration by setting GPIO pins */
    
    /* Audio amplifier enable pin */
    platform_gpio_init(12, GPIO_MODE_OUTPUT);
    platform_gpio_write(12, 0); /* Start with amplifier off */
    
    /* Microphone bias enable pin */
    platform_gpio_init(13, GPIO_MODE_OUTPUT);
    platform_gpio_write(13, 0); /* Start with mic bias off */
    
    /* Configure I2S pins (would be platform-specific) */
    platform_gpio_init(18, GPIO_MODE_OUTPUT); /* I2S BCLK */
    platform_gpio_init(19, GPIO_MODE_OUTPUT); /* I2S LRCLK */
    platform_gpio_init(20, GPIO_MODE_OUTPUT); /* I2S Data Out */
    platform_gpio_init(21, GPIO_MODE_INPUT);  /* I2S Data In */
    
    /* Setup audio interrupt timer (for sampling) */
    platform_timer_start(0, 1000 / (AUDIO_SAMPLE_RATE / 1000), 1, NULL, NULL);
    
    return 0;
}

/**
 * Start audio capture from microphone
 */
int audio_start_capture(void) {
    /* Check if already capturing */
    if (audio_state.state == AUDIO_STATE_CAPTURING || audio_state.state == AUDIO_STATE_BOTH) {
        return 0;
    }
    
    /* Enable microphone bias */
    platform_gpio_write(13, 1);
    
    /* In a real implementation, this would configure the ADC, DMA, etc. */
    
    /* Wait for mic bias to stabilize */
    platform_delay_ms(10);
    
    /* Update state */
    if (audio_state.state == AUDIO_STATE_IDLE) {
        audio_state.state = AUDIO_STATE_CAPTURING;
    } else if (audio_state.state == AUDIO_STATE_PLAYING) {
        audio_state.state = AUDIO_STATE_BOTH;
    }
    
    /* Reset buffer position */
    audio_state.buffer_pos = 0;
    
    return 0;
}

/**
 * Stop audio capture
 */
int audio_stop_capture(void) {
    /* Check if not capturing */
    if (audio_state.state == AUDIO_STATE_IDLE || audio_state.state == AUDIO_STATE_PLAYING) {
        return 0;
    }
    
    /* Disable microphone bias to save power */
    platform_gpio_write(13, 0);
    
    /* In a real implementation, this would stop the ADC, DMA, etc. */
    
    /* Update state */
    if (audio_state.state == AUDIO_STATE_CAPTURING) {
        audio_state.state = AUDIO_STATE_IDLE;
    } else if (audio_state.state == AUDIO_STATE_BOTH) {
        audio_state.state = AUDIO_STATE_PLAYING;
    }
    
    return 0;
}

/**
 * Start audio playback to speaker
 */
int audio_start_playback(void) {
    /* Check if already playing */
    if (audio_state.state == AUDIO_STATE_PLAYING || audio_state.state == AUDIO_STATE_BOTH) {
        return 0;
    }
    
    /* Enable audio amplifier */
    platform_gpio_write(12, 1);
    
    /* In a real implementation, this would configure the DAC, DMA, etc. */
    
    /* Update state */
    if (audio_state.state == AUDIO_STATE_IDLE) {
        audio_state.state = AUDIO_STATE_PLAYING;
    } else if (audio_state.state == AUDIO_STATE_CAPTURING) {
        audio_state.state = AUDIO_STATE_BOTH;
    }
    
    return 0;
}

/**
 * Stop audio playback
 */
int audio_stop_playback(void) {
    /* Check if not playing */
    if (audio_state.state == AUDIO_STATE_IDLE || audio_state.state == AUDIO_STATE_CAPTURING) {
        return 0;
    }
    
    /* Disable audio amplifier to save power */
    platform_gpio_write(12, 0);
    
    /* In a real implementation, this would stop the DAC, DMA, etc. */
    
    /* Update state */
    if (audio_state.state == AUDIO_STATE_PLAYING) {
        audio_state.state = AUDIO_STATE_IDLE;
    } else if (audio_state.state == AUDIO_STATE_BOTH) {
        audio_state.state = AUDIO_STATE_CAPTURING;
    }
    
    return 0;
}

/**
 * Process push-to-talk button state
 */
int audio_process_ptt(uint8_t ptt_state) {
    /* Check if state changed */
    if (audio_state.ptt_state == ptt_state) {
        return 0;
    }
    
    /* Update the PTT state */
    audio_state.ptt_state = ptt_state;
    
    if (ptt_state == PTT_PRESSED) {
        /* Start capturing when PTT is pressed */
        audio_start_capture();
        audio_stop_playback();
    } else {
        /* Stop capturing when PTT is released */
        audio_stop_capture();
        audio_start_playback();
    }
    
    return 0;
}

/**
 * Apply audio processing to samples
 */
static void apply_audio_processing(int16_t* samples, size_t count) {
    /* In a real implementation, this would apply various audio processing algorithms */
    
    /* For this simulation, we'll just do simple gain control */
    if (audio_state.agc_enabled) {
        /* Find peak value */
        int16_t peak = 0;
        for (size_t i = 0; i < count; i++) {
            int16_t abs_sample = abs(samples[i]);
            if (abs_sample > peak) {
                peak = abs_sample;
            }
        }
        
        /* Calculate gain factor to normalize */
        float gain = 1.0f;
        if (peak > 0) {
            gain = 0.8f * 32767.0f / peak;
            
            /* Limit gain to reasonable range */
            if (gain > 4.0f) gain = 4.0f;
            if (gain < 0.25f) gain = 0.25f;
            
            /* Apply gain */
            for (size_t i = 0; i < count; i++) {
                float sample = samples[i] * gain;
                if (sample > 32767.0f) sample = 32767.0f;
                if (sample < -32768.0f) sample = -32768.0f;
                samples[i] = (int16_t)sample;
            }
        }
    }
    
    /* Apply noise gate if enabled */
    if (audio_state.noise_gate_enabled) {
        /* Calculate RMS energy */
        float sum_squares = 0;
        for (size_t i = 0; i < count; i++) {
            sum_squares += samples[i] * samples[i];
        }
        float rms = sqrtf(sum_squares / count);
        
        /* Apply gate if RMS is below threshold */
        if (rms < audio_state.noise_gate_threshold) {
            memset(samples, 0, count * sizeof(int16_t));
        }
    }
    
    /* In a real implementation, additional processing like noise reduction,
     * echo cancellation, etc. would be applied here */
}

/**
 * Detect voice activity in the audio samples
 */
static int detect_voice_activity(const int16_t* samples, size_t count) {
    if (!audio_state.vad_enabled) {
        return 1; /* Always active if VAD is disabled */
    }
    
    /* Calculate average amplitude */
    uint32_t sum = 0;
    for (size_t i = 0; i < count; i++) {
        sum += abs(samples[i]);
    }
    uint16_t avg = sum / count;
    
    /* Detect activity based on threshold */
    uint8_t activity = avg > audio_state.vad_threshold;
    
    /* Apply hold time */
    if (activity) {
        audio_state.vad_active = 1;
        audio_state.vad_hold_counter = audio_state.vad_hold_frames;
    } else if (audio_state.vad_hold_counter > 0) {
        audio_state.vad_hold_counter--;
    } else {
        audio_state.vad_active = 0;
    }
    
    return audio_state.vad_active;
}

/**
 * Process a captured audio buffer
 */
int audio_process_captured(const int16_t* pcm_buffer, size_t samples) {
    /* Process in codec frame-sized chunks */
    size_t frames = samples / audio_state.samples_per_frame;
    size_t offset = 0;
    
    /* Copy to internal buffer */
    memcpy(audio_state.audio_buffer + audio_state.buffer_pos, pcm_buffer, samples * sizeof(int16_t));
    audio_state.buffer_pos += samples;
    
    /* Process complete frames */
    while (audio_state.buffer_pos >= audio_state.samples_per_frame) {
        /* Apply audio processing */
        int16_t processed_frame[320]; /* Max frame size is 320 samples */
        memcpy(processed_frame, audio_state.audio_buffer, audio_state.samples_per_frame * sizeof(int16_t));
        apply_audio_processing(processed_frame, audio_state.samples_per_frame);
        
        /* Check for voice activity */
        if (detect_voice_activity(processed_frame, audio_state.samples_per_frame)) {
            /* Encode the frame */
            uint8_t encoded[8]; /* Maximum encoded frame size */
            codec2_encode_frame(processed_frame, encoded);
            
            /* Queue for transmission if PTT is pressed */
            if (audio_state.ptt_state == PTT_PRESSED) {
                audio_queue_for_tx(encoded, audio_state.coded_frame_size);
            }
        }
        
        /* Remove the processed frame from the buffer */
        memmove(audio_state.audio_buffer, 
                audio_state.audio_buffer + audio_state.samples_per_frame,
                (audio_state.buffer_pos - audio_state.samples_per_frame) * sizeof(int16_t));
        audio_state.buffer_pos -= audio_state.samples_per_frame;
    }
    
    return 0;
}

/**
 * Encode an audio frame using Codec2
 */
static void codec2_encode_frame(const int16_t* input, uint8_t* output) {
#ifdef USE_CODEC2
    if (audio_state.codec2) {
        /* Use the actual Codec2 encoder */
        codec2_encode(audio_state.codec2, output, (short*)input);
        return;
    }
#endif

    /* Fallback implementation if Codec2 is not available */
    memset(output, 0, audio_state.coded_frame_size);
    
    /* Calculate frame energy (simple heuristic) */
    uint32_t energy = 0;
    for (size_t i = 0; i < audio_state.samples_per_frame; i++) {
        energy += abs(input[i]);
    }
    energy /= audio_state.samples_per_frame;
    
    /* First byte is energy */
    output[0] = (energy > 255) ? 255 : (uint8_t)energy;
    
    /* Remaining bytes encode spectral characteristics
     * This is a very simplified approximation of what Codec2 does */
    if (audio_state.samples_per_frame >= 160) {
        /* Divide the frame into segments and find peak frequency in each */
        uint8_t num_segments = audio_state.coded_frame_size - 1;
        size_t segment_size = audio_state.samples_per_frame / num_segments;
        
        for (uint8_t s = 0; s < num_segments; s++) {
            size_t start = s * segment_size;
            
            /* Extremely simplified spectral analysis */
            uint16_t low_energy = 0, high_energy = 0;
            for (size_t i = 0; i < segment_size / 2; i++) {
                low_energy += abs(input[start + i]);
            }
            for (size_t i = segment_size / 2; i < segment_size; i++) {
                high_energy += abs(input[start + i]);
            }
            
            /* Encode relative energy distribution */
            if (low_energy + high_energy > 0) {
                output[s + 1] = (uint8_t)((high_energy * 255) / (low_energy + high_energy));
            }
        }
    }
}

/**
 * Decode a Codec2 frame to PCM audio
 */
static void codec2_decode_frame(const uint8_t* input, int16_t* output) {
#ifdef USE_CODEC2
    if (audio_state.codec2) {
        /* Use the actual Codec2 decoder */
        codec2_decode(audio_state.codec2, (short*)output, (unsigned char*)input);
        return;
    }
#endif

    /* Fallback implementation if Codec2 is not available */
    memset(output, 0, audio_state.samples_per_frame * sizeof(int16_t));
    
    /* Get energy from first byte */
    uint8_t energy = input[0];
    
    /* Create a synthesized waveform based on the encoded data */
    if (energy > 0) {
        /* Generate a mix of frequencies based on the encoded spectral data */
        uint8_t num_segments = audio_state.coded_frame_size - 1;
        
        /* Simple signal synthesis with smoothing */
        for (size_t i = 0; i < audio_state.samples_per_frame; i++) {
            float sample = 0;
            uint8_t segment = (i * num_segments) / audio_state.samples_per_frame;
            uint8_t freq_value = (segment < num_segments) ? input[segment + 1] : 128;
            
            /* Generate a mix of sine waves based on the frequency value */
            float base_freq = 300.0f + freq_value * 2.5f;
            
            /* Primary frequency */
            sample += sinf(2.0f * M_PI * base_freq * i / AUDIO_SAMPLE_RATE) * 0.7f;
            
            /* Harmonics */
            sample += sinf(2.0f * M_PI * base_freq * 2 * i / AUDIO_SAMPLE_RATE) * 0.2f;
            sample += sinf(2.0f * M_PI * base_freq * 3 * i / AUDIO_SAMPLE_RATE) * 0.1f;
            
            /* Scale by energy */
            output[i] = (int16_t)(sample * energy * 80);
        }
        
        /* Apply envelope to avoid clicks */
        int16_t attack = audio_state.samples_per_frame / 32;
        int16_t release = audio_state.samples_per_frame / 16;
        
        /* Attack phase */
        for (int16_t i = 0; i < attack; i++) {
            float gain = (float)i / attack;
            output[i] = (int16_t)(output[i] * gain);
        }
        
        /* Release phase */
        for (int16_t i = 0; i < release; i++) {
            float gain = (float)(release - i) / release;
            output[audio_state.samples_per_frame - i - 1] = 
                (int16_t)(output[audio_state.samples_per_frame - i - 1] * gain);
        }
    }
}

/**
 * Encode an audio frame using Codec2
 */
int audio_encode_frame(const int16_t* pcm_samples, uint8_t* coded_bits) {
    if (!pcm_samples || !coded_bits) {
        return -1;
    }
    
    /* Encode using Codec2 */
    codec2_encode_frame(pcm_samples, coded_bits);
    
    return audio_state.coded_frame_size;
}

/**
 * Decode a Codec2 frame to PCM audio
 */
int audio_decode_frame(const uint8_t* coded_bits, int16_t* pcm_samples) {
    if (!coded_bits || !pcm_samples) {
        return -1;
    }
    
    /* Decode using Codec2 */
    codec2_decode_frame(coded_bits, pcm_samples);
    
    return audio_state.samples_per_frame;
}

/**
 * Queue an encoded audio frame for transmission
 */
int audio_queue_for_tx(const uint8_t* coded_bits, size_t size) {
    if (!coded_bits || size == 0 || size > 8) {
        return -1;
    }
    
    /* Check if the queue is full */
    if (audio_state.tx_queue_count >= TX_QUEUE_SIZE) {
        return -2;
    }
    
    /* Add to the TX queue */
    memcpy(audio_state.tx_queue[audio_state.tx_queue_tail].data, coded_bits, size);
    audio_state.tx_queue[audio_state.tx_queue_tail].size = size;
    
    /* Update queue pointers */
    audio_state.tx_queue_tail = (audio_state.tx_queue_tail + 1) % TX_QUEUE_SIZE;
    audio_state.tx_queue_count++;
    
    return 0;
}

/**
 * Queue received audio data for playback
 */
int audio_queue_for_playback(const uint8_t* coded_bits, size_t size) {
    if (!coded_bits || size == 0 || size > 8) {
        return -1;
    }
    
    /* Check if the queue is full */
    if (audio_state.rx_queue_count >= RX_QUEUE_SIZE) {
        return -2;
    }
    
    /* Add to the RX queue */
    memcpy(audio_state.rx_queue[audio_state.rx_queue_tail].data, coded_bits, size);
    audio_state.rx_queue[audio_state.rx_queue_tail].size = size;
    
    /* Update queue pointers */
    audio_state.rx_queue_tail = (audio_state.rx_queue_tail + 1) % RX_QUEUE_SIZE;
    audio_state.rx_queue_count++;
    
    /* Start playback if not already active */
    if (audio_state.state == AUDIO_STATE_IDLE || audio_state.state == AUDIO_STATE_CAPTURING) {
        audio_start_playback();
    }
    
    return 0;
}

/**
 * Get the next audio packet for transmission
 */
int audio_get_next_packet(uint8_t* packet_buffer, size_t max_size) {
    if (!packet_buffer || max_size == 0) {
        return -1;
    }
    
    /* Check if there are enough frames in the queue */
    if (audio_state.tx_queue_count == 0) {
        return 0; /* No data available */
    }
    
    /* Calculate how many frames to include in this packet */
    size_t frames_to_send = audio_state.tx_queue_count;
    if (frames_to_send > MAX_FRAMES_PER_PACKET) {
        frames_to_send = MAX_FRAMES_PER_PACKET;
    }
    
    /* Calculate total size needed */
    size_t total_size = frames_to_send * audio_state.coded_frame_size;
    if (total_size > max_size) {
        frames_to_send = max_size / audio_state.coded_frame_size;
        total_size = frames_to_send * audio_state.coded_frame_size;
    }
    
    /* If no frames can be sent, return */
    if (frames_to_send == 0) {
        return 0;
    }
    
    /* Format packet header - first byte contains metadata */
    uint8_t metadata = 0;
    metadata |= audio_state.codec_mode & 0x07;         /* 3 bits for codec mode */
    metadata |= (frames_to_send & 0x0F) << 3;          /* 4 bits for frame count */
    metadata |= (audio_state.vad_active ? 1 : 0) << 7; /* 1 bit for VAD status */
    
    packet_buffer[0] = metadata;
    
    /* Copy frames from the TX queue to the packet buffer */
    size_t offset = 1; /* Start after metadata byte */
    for (size_t i = 0; i < frames_to_send; i++) {
        /* Get the next frame from the queue */
        audio_frame_t* frame = &audio_state.tx_queue[audio_state.tx_queue_head];
        
        /* Copy frame data to the packet buffer */
        memcpy(packet_buffer + offset, frame->data, frame->size);
        offset += frame->size;
        
        /* Update queue pointers */
        audio_state.tx_queue_head = (audio_state.tx_queue_head + 1) % TX_QUEUE_SIZE;
        audio_state.tx_queue_count--;
    }
    
    return offset; /* Return total packet size */
}