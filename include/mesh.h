#ifndef MESH_H
#define MESH_H

#include <stdint.h>
#include <stddef.h>
#include "packet.h"

/**
 * @file mesh.h
 * @brief Mesh networking functionality
 */

/* Maximum number of nodes in routing table */
#define MAX_ROUTE_ENTRIES 32

/* Maximum time to keep a route entry (in milliseconds) */
#define ROUTE_TIMEOUT_MS 300000 /* 5 minutes */

/* Routing entry */
typedef struct {
    uint16_t dest_id;        /* Destination node ID */
    uint16_t next_hop;       /* Next hop node ID */
    uint8_t  hops;           /* Number of hops to destination */
    int8_t   rssi;           /* Signal strength of link */
    uint8_t  band;           /* Best band for this link */
    uint32_t last_updated;   /* Timestamp of last update */
} route_entry_t;

/* Neighbor node */
typedef struct {
    uint16_t node_id;        /* Node ID */
    uint8_t  bands;          /* Supported bands (bit mask) */
    int8_t   rssi[3];        /* RSSI per band */
    uint32_t last_seen;      /* Timestamp of last packet */
    uint8_t  battery_level;  /* Battery level (0-100%) */
    uint8_t  is_active;      /* Whether this neighbor is active */
} neighbor_t;

/**
 * Initialize the mesh networking subsystem
 * 
 * @param our_node_id The node ID for this device
 * @return 0 on success, negative on error
 */
int mesh_init(uint16_t our_node_id);

/**
 * Process a received packet for the mesh network
 * 
 * @param packet The received packet
 * @param rssi Signal strength of received packet
 * @param snr Signal-to-noise ratio of received packet
 * @return 0 on success, negative on error
 */
int mesh_process_packet(const packet_t* packet, int16_t rssi, int8_t snr);

/**
 * Send a packet through the mesh network
 * 
 * @param packet The packet to send
 * @return 0 on success, negative on error
 */
int mesh_send_packet(packet_t* packet);

/**
 * Find the best next hop for a destination
 * 
 * @param dest_id Destination node ID
 * @param best_band Pointer to store the best band for this route
 * @return Next hop node ID, or 0 if not found
 */
uint16_t mesh_find_next_hop(uint16_t dest_id, uint8_t* best_band);

/**
 * Update the routing table with information from a packet
 * 
 * @param source Source node ID
 * @param from_node Node ID we received this from (or 0 if direct)
 * @param rssi Signal strength
 * @param band Band this was received on
 * @return 0 on success, negative on error
 */
int mesh_update_routing(uint16_t source, uint16_t from_node, int16_t rssi, uint8_t band);

/**
 * Discover the network topology
 * 
 * @return Number of nodes discovered, or negative on error
 */
int mesh_discover(void);

/**
 * Send a broadcast packet to all nodes in range
 * 
 * @param type Packet type
 * @param payload Payload data
 * @param payload_len Length of payload in bytes
 * @param ttl Time to live (hop limit)
 * @return 0 on success, negative on error
 */
int mesh_broadcast(uint8_t type, const uint8_t* payload, size_t payload_len, uint8_t ttl);

/**
 * Get information about a neighbor node
 * 
 * @param node_id Node ID to query
 * @param neighbor Pointer to neighbor structure to fill
 * @return 0 on success, 1 if not found, negative on error
 */
int mesh_get_neighbor(uint16_t node_id, neighbor_t* neighbor);

/**
 * Update neighbor information
 * 
 * @param node_id Node ID to update
 * @param band Band this information is for
 * @param rssi Signal strength
 * @return 0 on success, negative on error
 */
int mesh_update_neighbor(uint16_t node_id, uint8_t band, int16_t rssi);

/**
 * Get the number of active neighbors
 * 
 * @return Number of active neighbors
 */
int mesh_count_neighbors(void);

/**
 * Prune old entries from the routing table
 * 
 * @return Number of entries pruned
 */
int mesh_prune_routes(void);

/**
 * Send a node beacon to announce our presence
 * 
 * @return 0 on success, negative on error
 */
int mesh_send_beacon(void);

#endif /* MESH_H */