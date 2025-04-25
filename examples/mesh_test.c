#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "radio_config.h"
#include "security.h"
#include "packet.h"
#include "radio.h"
#include "mesh.h"
#include "platform.h"

/* Packet types not defined in packet.h */
#define PACKET_TYPE_DATA          0x08  /* General data packet */

/* Our own implementations of missing mesh functions */

/* Discover neighbors in the network */
static int mesh_discover_neighbors(void) {
    /* Use the mesh_discover function that's in the API */
    return mesh_discover();
}

/* Print routing table - this is a custom function for the mesh_test example */
static void mesh_print_routing_table(void) {
    printf("Routing table would be printed here\n");
    /* Since we don't have access to the routing table internals,
       we can't implement this function properly in this example */
}

/* Process periodic tasks - called in the main loop */
static void mesh_process_tasks(void) {
    /* No-op function since the real implementation is internal to mesh.c */
}

/* Helper function to initialize packet header */
static void packet_init_header(packet_header_t *header, uint16_t source, uint16_t dest, uint8_t type) {
    header->source = source;
    header->destination = dest;
    header->type = type;
    header->ttl = 3; /* Default TTL */
    header->sequence = 0; /* Will be filled by packet_create */
    header->band_info = 0;
    header->multi_band_flags = 0;
    header->nonce_fragment = 0;
}

/* Global state */
static volatile int running = 1;
static uint16_t node_id = 0;
static uint16_t target_node = BROADCAST_ADDR;

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
    uint8_t test_mode = 0;
    
    int opt;
    while ((opt = getopt(argc, argv, "i:t:r:e:s:m:h")) != -1) {
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
            case 'm':
                test_mode = (uint8_t)strtol(optarg, NULL, 0);
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
    
    printf("Meridian Mesh Network Test\n");
    printf("Node ID: 0x%04X\n", node_id);
    
    if (target_node != BROADCAST_ADDR) {
        printf("Target: 0x%04X\n", target_node);
    } else {
        printf("Target: Broadcast\n");
    }
    
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
    
    printf("Radio initialized on band %d, frequency %d MHz\n", 
           config.band, config.frequency / 1000000);
    printf("Spreading factor: %d, Bandwidth: %d kHz\n",
           config.spreadFactor, config.bandwidth);
    printf("Press Ctrl+C to exit\n");
    
    /* Print available commands based on test mode */
    if (test_mode == 0) {
        printf("Available commands:\n");
        printf("  b - Send broadcast beacon\n");
        printf("  d - Discover neighbors\n");
        printf("  r - Print routing table\n");
        printf("  s - Send test message to target\n");
        printf("  c - Check channel activity\n");
        printf("  n - Measure noise floor\n");
        printf("  q - Quit\n");
    } else if (test_mode == 1) {
        printf("Auto-discovery mode active - will periodically scan for neighbors\n");
    } else if (test_mode == 2) {
        printf("Continuous transmission mode - sending beacons every 10 seconds\n");
    }
    
    uint32_t last_action_time = 0;
    uint32_t action_interval = (test_mode == 1) ? 30000 : 10000; /* 30s for discovery, 10s for beacons */
    
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
                switch (cmd) {
                    case 'b': {
                        /* Send beacon */
                        printf("Sending broadcast beacon...\n");
                        packet_t packet;
                        packet_init_header(&packet.header, node_id, BROADCAST_ADDR, PACKET_TYPE_BEACON);
                        
                        /* Add some beacon data */
                        packet.payload_len = 4;
                        packet.payload[0] = 0x01; /* Version */
                        packet.payload[1] = 0x02; /* Battery level (example) */
                        packet.payload[2] = 0x03; /* Signal strength (example) */
                        packet.payload[3] = 0x04; /* Node capability flags */
                        
                        /* Serialize and send */
                        uint8_t buffer[MAX_PACKET_SIZE];
                        size_t size = packet_serialize(&packet, buffer, MAX_PACKET_SIZE);
                        
                        /* Switch to TX mode and send */
                        radio_transmit(buffer, size, 0);
                        break;
                    }
                    
                    case 'd':
                        /* Discover neighbors */
                        printf("Starting neighbor discovery...\n");
                        mesh_discover_neighbors();
                        break;
                    
                    case 'r':
                        /* Print routing table */
                        printf("Mesh routing table:\n");
                        mesh_print_routing_table();
                        break;
                    
                    case 's': {
                        /* Send test message to target */
                        if (target_node == BROADCAST_ADDR) {
                            printf("Error: Target node must be specified for sending test message\n");
                            break;
                        }
                        
                        printf("Sending test message to node 0x%04X...\n", target_node);
                        
                        packet_t packet;
                        packet_init_header(&packet.header, node_id, target_node, PACKET_TYPE_DATA);
                        
                        /* Add test message */
                        const char *message = "Test message from mesh network";
                        packet.payload_len = strlen(message) + 1;
                        memcpy(packet.payload, message, packet.payload_len);
                        
                        /* Serialize and send through mesh routing */
                        if (mesh_send_packet(&packet) != 0) {
                            printf("Error: Failed to send packet through mesh network\n");
                        }
                        break;
                    }
                    
                    case 'c': {
                        /* Check channel activity */
                        printf("Checking channel activity...\n");
                        int result = radio_check_channel();
                        if (result < 0) {
                            printf("Error checking channel\n");
                        } else if (result == 1) {
                            printf("Channel is active (signal detected)\n");
                        } else {
                            printf("Channel is clear (no signal detected)\n");
                        }
                        break;
                    }
                    
                    case 'n': {
                        /* Measure noise floor */
                        printf("Measuring noise floor...\n");
                        int16_t noise = radio_measure_noise_floor();
                        printf("Noise floor: %d dBm\n", noise);
                        break;
                    }
                    
                    case 'q':
                        /* Quit */
                        running = 0;
                        break;
                }
            }
        }
        
        /* Automatic actions for test modes */
        uint32_t current_time = platform_get_time_ms();
        if (test_mode > 0 && (current_time - last_action_time) >= action_interval) {
            if (test_mode == 1) {
                /* Auto-discovery mode */
                printf("Auto-discovery: Scanning for neighbors...\n");
                mesh_discover_neighbors();
            } else if (test_mode == 2) {
                /* Continuous beacon mode */
                printf("Sending periodic beacon...\n");
                
                packet_t packet;
                packet_init_header(&packet.header, node_id, BROADCAST_ADDR, PACKET_TYPE_BEACON);
                
                /* Add some beacon data */
                packet.payload_len = 4;
                packet.payload[0] = 0x01; /* Version */
                packet.payload[1] = 0x02; /* Battery level (example) */
                packet.payload[2] = 0x03; /* Signal strength (example) */
                packet.payload[3] = 0x04; /* Node capability flags */
                
                /* Serialize and send */
                uint8_t buffer[MAX_PACKET_SIZE];
                size_t size = packet_serialize(&packet, buffer, MAX_PACKET_SIZE);
                
                /* Switch to TX mode and send */
                radio_transmit(buffer, size, 0);
            }
            
            last_action_time = current_time;
        }
        
        /* Process any mesh networking tasks */
        mesh_process_tasks();
        
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
    
    /* Print additional info based on packet type */
    switch (packet.header.type) {
        case PACKET_TYPE_BEACON:
            printf("Beacon from node 0x%04X\n", packet.header.source);
            break;
            
        case PACKET_TYPE_DATA:
            if (packet.header.destination == node_id || packet.header.destination == BROADCAST_ADDR) {
                printf("Data packet from node 0x%04X: %s\n", 
                       packet.header.source, (char*)packet.payload);
            } else {
                printf("Forwarded data packet from 0x%04X to 0x%04X\n", 
                       packet.header.source, packet.header.destination);
            }
            break;
            
        case PACKET_TYPE_VOICE:
            printf("Voice packet from node 0x%04X (%zu bytes)\n", 
                   packet.header.source, packet.payload_len);
            break;
            
        case PACKET_TYPE_CONTROL:
            printf("Control packet from node 0x%04X\n", packet.header.source);
            break;
            
        default:
            printf("Unknown packet type %d from node 0x%04X\n", 
                   packet.header.type, packet.header.source);
            break;
    }
}

/* Callback for completed transmissions */
static void radio_tx_callback(void) {
    printf("Transmission complete\n");
    radio_set_rx(0); /* Go back to continuous receive mode */
}

/* Print help information */
static void print_help(void) {
    printf("Usage: mesh_test -i <node_id> [options]\n");
    printf("Options:\n");
    printf("  -i <id>     Set node ID (required, hexadecimal)\n");
    printf("  -t <id>     Set target node ID (default: broadcast)\n");
    printf("  -r <region> Set regulatory region (0-3)\n");
    printf("  -e <terrain> Set terrain type (0-3)\n");
    printf("  -s <mode>   Set security mode (0-2)\n");
    printf("  -m <mode>   Set test mode (0-2)\n");
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
    printf("\nTest modes:\n");
    printf("  0: Interactive mode (default)\n");
    printf("  1: Auto-discovery mode\n");
    printf("  2: Continuous beacon transmission mode\n");
}