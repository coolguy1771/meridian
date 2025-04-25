#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "radio_config.h"
#include "security.h"
#include "packet.h"
#include "audio.h"
#include "radio.h"
#include "mesh.h"

/* Global state */
static volatile int running = 1;
static uint16_t node_id = 0;
static uint16_t target_node = BROADCAST_ADDR;
static uint8_t ptt_state = PTT_RELEASED;

/* Function prototypes */
static void signal_handler(int sig);
static void radio_rx_callback(uint8_t* buffer, size_t size, int16_t rssi, int8_t snr);
static void radio_tx_callback(void);
static void print_help(void);

int main(int argc, char *argv[]) {
    /* Parse command line arguments */
    uint8_t region = REGION_AMERICAS;
    uint8_t terrain = TERRAIN_MIXED;
    uint8_t security_mode = SECURITY_E2E_AUTH;
    uint8_t codec_mode = CODEC2_MODE_1600;
    
    int opt;
    while ((opt = getopt(argc, argv, "i:t:r:e:s:c:h")) != -1) {
        switch (opt) {
            case 'i':
                node_id = (uint16_t)strtol(optarg, NULL, 0);
                break;
            case 't':
                target_node = (uint16_t)strtol(optarg, NULL, 0);
                break;
            case 'r':
                region = (uint8_t)strtol(optarg, NULL, 0);
                break;
            case 'e':
                terrain = (uint8_t)strtol(optarg, NULL, 0);
                break;
            case 's':
                security_mode = (uint8_t)strtol(optarg, NULL, 0);
                break;
            case 'c':
                codec_mode = (uint8_t)strtol(optarg, NULL, 0);
                break;
            case 'h':
                print_help();
                return 0;
            default:
                fprintf(stderr, "Unknown option: %c\n", opt);
                print_help();
                return 1;
        }
    }
    
    /* Check required parameters */
    if (node_id == 0) {
        fprintf(stderr, "Error: Node ID must be specified\n");
        print_help();
        return 1;
    }
    
    printf("Adaptive Radio Voice Chat\n");
    printf("Node ID: 0x%04X\n", node_id);
    printf("Target: %s\n", target_node == BROADCAST_ADDR ? "Broadcast" : "Node");
    
    /* Initialize subsystems */
    if (radio_config_init(region, terrain) != 0) {
        fprintf(stderr, "Failed to initialize radio configuration\n");
        return 1;
    }
    
    if (security_init(security_mode, CIPHER_AES_GCM) != 0) {
        fprintf(stderr, "Failed to initialize security\n");
        return 1;
    }
    
    if (packet_init(node_id) != 0) {
        fprintf(stderr, "Failed to initialize packet handling\n");
        return 1;
    }
    
    if (audio_init(codec_mode) != 0) {
        fprintf(stderr, "Failed to initialize audio\n");
        return 1;
    }
    
    if (mesh_init(node_id) != 0) {
        fprintf(stderr, "Failed to initialize mesh networking\n");
        return 1;
    }
    
    /* Get optimal radio configuration */
    radio_config_t config;
    if (radio_config_get_optimal(&config) != 0) {
        fprintf(stderr, "Failed to get optimal radio configuration\n");
        return 1;
    }
    
    /* Initialize radio with optimal configuration */
    if (radio_init(&config) != 0) {
        fprintf(stderr, "Failed to initialize radio\n");
        return 1;
    }
    
    /* Set up radio callbacks */
    radio_set_rx_callback(radio_rx_callback);
    radio_set_tx_callback(radio_tx_callback);
    
    /* Set up signal handler for clean shutdown */
    signal(SIGINT, signal_handler);
    
    /* Start in receive mode */
    radio_set_rx(0); /* Continuous receive */
    audio_start_playback();
    
    printf("Radio initialized on band %d, frequency %d MHz\n", 
           config.band, config.frequency / 1000000);
    printf("Press Ctrl+C to exit\n");
    printf("Press 'p' for PTT, 'r' to release\n");
    
    /* Main loop */
    char cmd;
    while (running) {
        /* Read a command from stdin (non-blocking) */
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000; /* 100ms timeout */
        
        if (select(STDIN_FILENO + 1, &read_fds, NULL, NULL, &tv) > 0) {
            if (read(STDIN_FILENO, &cmd, 1) > 0) {
                if (cmd == 'p' && ptt_state == PTT_RELEASED) {
                    /* Press PTT */
                    ptt_state = PTT_PRESSED;
                    printf("PTT pressed - transmitting\n");
                    audio_process_ptt(ptt_state);
                } else if (cmd == 'r' && ptt_state == PTT_PRESSED) {
                    /* Release PTT */
                    ptt_state = PTT_RELEASED;
                    printf("PTT released - receiving\n");
                    audio_process_ptt(ptt_state);
                } else if (cmd == 'q') {
                    /* Quit */
                    running = 0;
                }
            }
        }
        
        /* Periodic tasks */
        /* Update environmental measurements (in a real system) */
        /* Send beacon periodically */
        /* etc. */
        
        usleep(10000); /* 10ms */
    }
    
    /* Cleanup */
    printf("Shutting down...\n");
    radio_set_idle();
    
    return 0;
}

/* Signal handler for Ctrl+C */
static void signal_handler(int sig) {
    running = 0;
}

/* Callback for received packets */
static void radio_rx_callback(uint8_t* buffer, size_t size, int16_t rssi, int8_t snr) {
    printf("Received packet: %zu bytes, RSSI: %d dBm, SNR: %d dB\n", size, rssi, snr);
    
    /* Parse the packet */
    packet_t packet;
    if (packet_deserialize(buffer, size, &packet) != 0) {
        printf("Failed to parse packet\n");
        return;
    }
    
    /* Process through mesh logic */
    int result = mesh_process_packet(&packet, rssi, snr);
    
    /* If it's a voice packet for us, queue it for playback */
    if ((result == 0 || result == 2) && packet.header.type == PACKET_TYPE_VOICE) {
        /* In a real implementation, we would decrypt the packet here */
        printf("Voice packet from node 0x%04X\n", packet.header.source);
        
        /* Queue for playback */
        audio_queue_for_playback(packet.payload, packet.payload_len);
    }
}

/* Callback for completed transmissions */
static void radio_tx_callback(void) {
    printf("Transmission complete\n");
    
    /* If PTT is released, go back to receive mode */
    if (ptt_state == PTT_RELEASED) {
        radio_set_rx(0);
    }
}

/* Print help information */
static void print_help(void) {
    printf("Usage: voice_chat -i <node_id> [options]\n");
    printf("Options:\n");
    printf("  -i <id>     Set node ID (required, hexadecimal)\n");
    printf("  -t <id>     Set target node ID (default: broadcast)\n");
    printf("  -r <region> Set regulatory region (0-3)\n");
    printf("  -e <terrain> Set terrain type (0-3)\n");
    printf("  -s <mode>   Set security mode (0-2)\n");
    printf("  -c <mode>   Set codec mode (0-4)\n");
    printf("  -h          Show this help\n");
    printf("\nRegions:\n");
    printf("  0: Americas (915 MHz)\n");
    printf("  1: Europe (868 MHz)\n");
    printf("  2: Asia\n");
    printf("  3: Global\n");
    printf("\nTerrain types:\n");
    printf("  0: Urban\n");
    printf("  1: Open field/desert\n");
    printf("  2: Forest/dense vegetation\n");
    printf("  3: Mixed terrain\n");
    printf("\nSecurity modes:\n");
    printf("  0: None (testing only)\n");
    printf("  1: End-to-end encryption\n");
    printf("  2: End-to-end with authentication\n");
    printf("\nCodec modes:\n");
    printf("  0: 3200 bits/s\n");
    printf("  1: 2400 bits/s\n");
    printf("  2: 1600 bits/s\n");
    printf("  3: 1300 bits/s\n");
    printf("  4: 700 bits/s\n");
}