#include "mesh.h"
#include "packet.h"
#include "radio.h"
#include "radio_config.h"
#include "security.h"
#include "platform.h"
#include <string.h>

/* Neighbor information */
#define MAX_NEIGHBORS 16

/* Routing table entry states */
#define ROUTE_STATE_INVALID 0
#define ROUTE_STATE_DIRECT 1
#define ROUTE_STATE_INDIRECT 2
#define ROUTE_STATE_STALE 3

/* Beacon intervals */
#define BEACON_INTERVAL_MS 60000      /* Regular beacons every 60 seconds */
#define DISCOVERY_BEACON_COUNT 3      /* Number of rapid beacons during discovery */
#define DISCOVERY_BEACON_DELAY_MS 500 /* Delay between discovery beacons */

/* Timeouts */
#define NEIGHBOR_TIMEOUT_MS 300000 /* Consider neighbors inactive after 5 minutes */
/* Local override for mesh.h value */
#define MESH_ROUTE_TIMEOUT_MS 600000    /* Consider routes expired after 10 minutes */

/* Radio callbacks */
static void mesh_rx_handler(uint8_t *data, size_t len, int16_t rssi, int8_t snr);
static void mesh_tx_handler(void);
static void mesh_error_handler(uint16_t error);

/* Module state */
static struct
{
    uint16_t our_node_id;
    route_entry_t routes[MAX_ROUTE_ENTRIES];
    neighbor_t neighbors[MAX_NEIGHBORS];
    uint32_t last_beacon_time;
    uint32_t last_route_cleanup;
    uint8_t scanning_band;
    uint8_t active_band;
    uint8_t network_key[SYMMETRIC_KEY_LENGTH];
    uint8_t discovery_mode;
    uint8_t discovery_count;
    uint8_t tx_in_progress;

    /* Band usage statistics */
    struct
    {
        uint16_t tx_count;
        uint16_t rx_count;
        uint16_t error_count;
        int16_t avg_rssi;
        int8_t avg_snr;
        uint8_t noise_floor;
    } band_stats[3];

    /* Application callbacks */
    void (*rx_callback)(const packet_t *packet, int16_t rssi, int8_t snr);
} mesh_state;

/* Forward declarations for internal functions */
static int mesh_send_packet_internal(packet_t *packet);
static int mesh_add_route(uint16_t dest_id, uint16_t next_hop, uint8_t hops, int8_t rssi, uint8_t band);
static int mesh_find_route_index(uint16_t dest_id);
static int mesh_add_neighbor(uint16_t node_id, uint8_t band, int16_t rssi);
static int mesh_find_neighbor_index(uint16_t node_id);
static int mesh_select_best_band(uint16_t dest_id);
static int mesh_update_band_stats(uint8_t band, int16_t rssi, int8_t snr, uint8_t is_rx);
static void mesh_periodic_tasks(void);

/**
 * Initialize the mesh networking subsystem
 */
int mesh_init(uint16_t our_node_id)
{
    /* Initialize state */
    memset(&mesh_state, 0, sizeof(mesh_state));
    mesh_state.our_node_id = our_node_id;
    mesh_state.last_beacon_time = 0;
    mesh_state.last_route_cleanup = 0;
    mesh_state.active_band = BAND_433MHZ; /* Start with 433 MHz as default */
    mesh_state.discovery_mode = 0;
    mesh_state.tx_in_progress = 0;

    /* Initialize routes and neighbors as empty */
    for (int i = 0; i < MAX_ROUTE_ENTRIES; i++)
    {
        mesh_state.routes[i].dest_id = 0; /* 0 means unused entry */
    }

    for (int i = 0; i < MAX_NEIGHBORS; i++)
    {
        mesh_state.neighbors[i].node_id = 0; /* 0 means unused entry */
    }

    /* Initialize band statistics */
    for (int i = 0; i < 3; i++)
    {
        mesh_state.band_stats[i].tx_count = 0;
        mesh_state.band_stats[i].rx_count = 0;
        mesh_state.band_stats[i].error_count = 0;
        mesh_state.band_stats[i].avg_rssi = -100;
        mesh_state.band_stats[i].avg_snr = 0;
        mesh_state.band_stats[i].noise_floor = 120; /* -120 dBm */
    }

    /* Initialize radio */
    radio_config_t config;
    switch (mesh_state.active_band)
    {
    case BAND_433MHZ:
        config = BAND_CONFIG_433MHZ;
        break;
    case BAND_868MHZ:
        config = BAND_CONFIG_868MHZ;
        break;
    case BAND_915MHZ:
        config = BAND_CONFIG_915MHZ;
        break;
    default:
        config = BAND_CONFIG_433MHZ;
        break;
    }

    if (radio_init(&config) != 0)
    {
        return -1;
    }

    /* Register radio callbacks */
    radio_set_rx_callback(mesh_rx_handler);
    radio_set_tx_callback(mesh_tx_handler);
    radio_set_error_callback(mesh_error_handler);

    /* Start listening */
    radio_set_rx(0); /* Continuous receive mode */

    /* Generate a temporary network key (in a real system this would be pre-shared) */
    platform_random_bytes(mesh_state.network_key, SYMMETRIC_KEY_LENGTH);

    /* Send an initial beacon */
    mesh_send_beacon();

    return 0;
}

/**
 * Set application callback for received packets
 */
int mesh_set_rx_callback(void (*callback)(const packet_t *packet, int16_t rssi, int8_t snr))
{
    mesh_state.rx_callback = callback;
    return 0;
}

/**
 * Process a received packet for the mesh network
 */
int mesh_process_packet(const packet_t *packet, int16_t rssi, int8_t snr)
{
    if (!packet)
    {
        return -1;
    }

    /* Extract the band information from the packet header */
    uint8_t band = packet->header.band_info & 0x03; /* Lower 2 bits indicate band */

    /* Update routing information */
    mesh_update_routing(packet->header.source, 0, rssi, band);

    /* Update stats for this band */
    mesh_update_band_stats(band, rssi, snr, 1);

    /* Process different packet types */
    switch (packet->header.type)
    {
    case PACKET_TYPE_BEACON:
        /* Process network beacon - update neighbor information */
        if (packet->payload_len >= 2)
        {
            /* Extract supported bands from beacon */
            uint8_t supported_bands = packet->payload[0];
            uint8_t battery_level = packet->payload[1];

            /* Find or create neighbor entry */
            int neighbor_idx = mesh_find_neighbor_index(packet->header.source);
            if (neighbor_idx >= 0)
            {
                /* Update existing neighbor */
                mesh_state.neighbors[neighbor_idx].bands = supported_bands;
                mesh_state.neighbors[neighbor_idx].battery_level = battery_level;
                mesh_state.neighbors[neighbor_idx].rssi[band] = rssi;
                mesh_state.neighbors[neighbor_idx].last_seen = platform_get_time_ms();
                mesh_state.neighbors[neighbor_idx].is_active = 1;
            }
            else
            {
                /* Add new neighbor */
                mesh_add_neighbor(packet->header.source, band, rssi);
            }

            /* If in discovery mode, send a response beacon */
            if (mesh_state.discovery_mode && packet->payload_len >= 3 && packet->payload[2] == 1)
            {
                /* Small delay to avoid collisions */
                platform_delay_ms(50 + (mesh_state.our_node_id % 50));
                mesh_send_beacon();
            }
        }
        break;

    default:
        /* For all other packet types, pass to application callback if registered */
        if (mesh_state.rx_callback)
        {
            mesh_state.rx_callback(packet, rssi, snr);
        }
        break;
    }

    /* Perform periodic tasks */
    mesh_periodic_tasks();

    return 0;
}

/**
 * Send a packet through the mesh network
 */
int mesh_send_packet(packet_t *packet)
{
    if (!packet)
    {
        return -1;
    }

    /* Don't allow sending while another transmission is in progress */
    if (mesh_state.tx_in_progress)
    {
        return -2;
    }

    /* Get current time for TTL purposes */
    uint32_t current_time = platform_get_time_ms();

    /* Perform periodic tasks */
    mesh_periodic_tasks();

    /* If it's a broadcast packet, send it directly */
    if (packet->header.destination == BROADCAST_ADDR)
    {
        return mesh_send_packet_internal(packet);
    }

    /* For unicast packets, find the next hop */
    uint8_t best_band;
    uint16_t next_hop = mesh_find_next_hop(packet->header.destination, &best_band);

    if (next_hop == 0)
    {
        /* No route to destination */
        return -3;
    }

    /* Update band info in header */
    packet->header.band_info = (packet->header.band_info & 0xFC) | (best_band & 0x03);

    /* Select the best band for this transmission */
    if (best_band != mesh_state.active_band)
    {
        /* Need to switch bands */
        radio_switch_band(best_band);
        mesh_state.active_band = best_band;
    }

    /* Send the packet */
    return mesh_send_packet_internal(packet);
}

/**
 * Internal function to actually transmit a packet
 */
static int mesh_send_packet_internal(packet_t *packet)
{
    /* Encrypt with the mesh network key */
    if (packet_encrypt(packet, mesh_state.network_key) != 0)
    {
        return -1;
    }

    /* Serialize the packet for transmission */
    uint8_t tx_buffer[MAX_PACKET_SIZE];
    int tx_len = packet_serialize(packet, tx_buffer, sizeof(tx_buffer));

    if (tx_len <= 0)
    {
        return -2;
    }

    /* Mark transmission in progress */
    mesh_state.tx_in_progress = 1;

    /* Update stats for this band */
    mesh_update_band_stats(mesh_state.active_band, 0, 0, 0);

    /* Transmit the packet */
    return radio_transmit(tx_buffer, tx_len, 2000); /* 2 second timeout */
}

/**
 * Find the best next hop for a destination
 */
uint16_t mesh_find_next_hop(uint16_t dest_id, uint8_t *best_band)
{
    if (dest_id == 0 || dest_id == mesh_state.our_node_id)
    {
        return 0; /* Invalid destination or ourselves */
    }

    /* Check if we know this destination directly */
    int neighbor_idx = mesh_find_neighbor_index(dest_id);
    if (neighbor_idx >= 0 && mesh_state.neighbors[neighbor_idx].is_active)
    {
        /* Determine best band for direct communication */
        int8_t best_rssi = -128;
        *best_band = BAND_433MHZ; /* Default to 433 MHz */

        for (int b = 0; b < 3; b++)
        {
            if (mesh_state.neighbors[neighbor_idx].rssi[b] > best_rssi &&
                (mesh_state.neighbors[neighbor_idx].bands & (1 << b)))
            {
                best_rssi = mesh_state.neighbors[neighbor_idx].rssi[b];
                *best_band = b;
            }
        }

        return dest_id; /* Direct connection */
    }

    /* Otherwise look up in routing table */
    int route_idx = mesh_find_route_index(dest_id);
    if (route_idx >= 0)
    {
        *best_band = mesh_state.routes[route_idx].band;
        return mesh_state.routes[route_idx].next_hop;
    }

    /* No route found */
    return 0;
}

/**
 * Update the routing table with information from a packet
 */
int mesh_update_routing(uint16_t source, uint16_t from_node, int16_t rssi, uint8_t band)
{
    if (source == 0 || source == mesh_state.our_node_id)
    {
        return -1; /* Invalid source or ourselves */
    }

    /* If we received this directly (from_node == 0), update neighbor info */
    if (from_node == 0)
    {
        mesh_add_neighbor(source, band, rssi);

        /* Add/update direct route */
        mesh_add_route(source, source, 1, rssi, band);
    }
    else
    {
        /* Add/update indirect route via from_node */
        /* Find the route to from_node to determine hop count */
        int via_idx = mesh_find_route_index(from_node);
        if (via_idx >= 0)
        {
            uint8_t hops = mesh_state.routes[via_idx].hops + 1;
            if (hops <= MAX_TTL)
            {
                mesh_add_route(source, from_node, hops, rssi, band);
            }
        }
    }

    return 0;
}

/**
 * Discover the network topology
 */
int mesh_discover(void)
{
    /* Enter discovery mode */
    mesh_state.discovery_mode = 1;
    mesh_state.discovery_count = 0;

    /* Send multiple discovery beacons with short delays between them */
    for (int i = 0; i < DISCOVERY_BEACON_COUNT; i++)
    {
        /* Create beacon payload - include band capabilities, battery level, and discovery flag */
        uint8_t payload[4];
        payload[0] = 0x07; /* Support all three bands - bits 0,1,2 for 433, 868, 915 MHz */
        payload[1] = 100;  /* Battery level 100% */
        payload[2] = 1;    /* Discovery mode flag */
        payload[3] = 0;    /* Reserved */

        /* Send the beacon as a broadcast */
        packet_t packet;
        packet_create(&packet, BROADCAST_ADDR, PACKET_TYPE_BEACON, payload, sizeof(payload));

        /* Set TTL and band */
        packet.header.ttl = 1;
        packet.header.band_info = mesh_state.active_band & 0x03;

        /* Send the packet */
        mesh_send_packet_internal(&packet);

        /* Wait for responses */
        platform_delay_ms(DISCOVERY_BEACON_DELAY_MS);
    }

    /* Exit discovery mode */
    mesh_state.discovery_mode = 0;

    /* Return the number of neighbors found */
    return mesh_count_neighbors();
}

/**
 * Send a broadcast packet to all nodes in range
 */
int mesh_broadcast(uint8_t type, const uint8_t *payload, size_t payload_len, uint8_t ttl)
{
    if (!payload || payload_len > MAX_PAYLOAD_SIZE)
    {
        return -1;
    }

    /* Create a broadcast packet */
    packet_t packet;
    if (packet_create(&packet, BROADCAST_ADDR, type, payload, payload_len) != 0)
    {
        return -2;
    }

    /* Set TTL and band */
    packet.header.ttl = ttl;
    packet.header.band_info = mesh_state.active_band & 0x03;

    /* Send it through the mesh */
    return mesh_send_packet(&packet);
}

/**
 * Get information about a neighbor node
 */
int mesh_get_neighbor(uint16_t node_id, neighbor_t *neighbor)
{
    if (!neighbor)
    {
        return -1;
    }

    /* Find the neighbor entry */
    int idx = mesh_find_neighbor_index(node_id);
    if (idx < 0)
    {
        return 1; /* Not found */
    }

    /* Copy the information */
    *neighbor = mesh_state.neighbors[idx];

    return 0;
}

/**
 * Update neighbor information
 */
int mesh_update_neighbor(uint16_t node_id, uint8_t band, int16_t rssi)
{
    return mesh_add_neighbor(node_id, band, rssi);
}

/**
 * Get the number of active neighbors
 */
int mesh_count_neighbors(void)
{
    int count = 0;
    uint32_t current_time = platform_get_time_ms();

    for (int i = 0; i < MAX_NEIGHBORS; i++)
    {
        if (mesh_state.neighbors[i].node_id != 0)
        {
            /* Check if this neighbor is still active */
            if (current_time - mesh_state.neighbors[i].last_seen < NEIGHBOR_TIMEOUT_MS)
            {
                count++;
            }
            else
            {
                /* Mark as inactive */
                mesh_state.neighbors[i].is_active = 0;
            }
        }
    }

    return count;
}

/**
 * Prune old entries from the routing table
 */
int mesh_prune_routes(void)
{
    int pruned = 0;
    uint32_t current_time = platform_get_time_ms();

    for (int i = 0; i < MAX_ROUTE_ENTRIES; i++)
    {
        if (mesh_state.routes[i].dest_id != 0)
        {
            /* Check if this route has expired */
            if (current_time - mesh_state.routes[i].last_updated > MESH_ROUTE_TIMEOUT_MS)
            {
                /* Clear this entry */
                mesh_state.routes[i].dest_id = 0;
                pruned++;
            }
        }
    }

    return pruned;
}

/**
 * Send a node beacon to announce our presence
 */
int mesh_send_beacon(void)
{
    uint32_t current_time = platform_get_time_ms();

    /* Only send beacons at the defined interval unless in discovery mode */
    if (!mesh_state.discovery_mode &&
        mesh_state.last_beacon_time > 0 &&
        current_time - mesh_state.last_beacon_time < BEACON_INTERVAL_MS)
    {
        return 0; /* Not time yet */
    }

    /* Update beacon timestamp */
    mesh_state.last_beacon_time = current_time;

    /* Create beacon payload - include band capabilities and battery level */
    uint8_t payload[4];
    payload[0] = 0x07;                              /* Support all three bands - bits 0,1,2 for 433, 868, 915 MHz */
    payload[1] = 100;                               /* Battery level 100% */
    payload[2] = mesh_state.discovery_mode ? 1 : 0; /* Discovery mode flag */
    payload[3] = 0;                                 /* Reserved */

    /* Send the beacon as a broadcast */
    return mesh_broadcast(PACKET_TYPE_BEACON, payload, sizeof(payload), 1);
}

/**
 * Radio receive callback
 */
static void mesh_rx_handler(uint8_t *data, size_t len, int16_t rssi, int8_t snr)
{
    /* Parse the received packet */
    packet_t packet;
    if (packet_deserialize(data, len, &packet) != 0)
    {
        return; /* Invalid packet */
    }

    /* Decrypt the packet */
    if (packet_decrypt(&packet, mesh_state.network_key) != 0)
    {
        return; /* Decryption failed */
    }

    /* Determine if the packet is for us */
    int result = packet_handle(&packet, 0); /* Direct reception */

    if (result == 0 || result == 2)
    {
        /* Packet is for us or broadcast - process it */
        mesh_process_packet(&packet, rssi, snr);
    }

    if (result == 1 || result == 2)
    {
        /* Packet needs to be forwarded */
        /* Decrement TTL */
        packet.header.ttl--;

        /* Forward the packet */
        mesh_send_packet(&packet);
    }
}

/**
 * Radio transmit callback
 */
static void mesh_tx_handler(void)
{
    /* Transmission complete */
    mesh_state.tx_in_progress = 0;

    /* Go back to receive mode */
    radio_set_rx(0);
}

/**
 * Radio error callback
 */
static void mesh_error_handler(uint16_t error)
{
    /* Update error statistics */
    mesh_state.band_stats[mesh_state.active_band].error_count++;

    /* Reset state */
    mesh_state.tx_in_progress = 0;

    /* Go back to receive mode */
    radio_set_rx(0);
}

/**
 * Add or update a route in the routing table
 */
static int mesh_add_route(uint16_t dest_id, uint16_t next_hop, uint8_t hops, int8_t rssi, uint8_t band)
{
    if (dest_id == 0 || next_hop == 0)
    {
        return -1;
    }

    /* Check if route already exists */
    int idx = mesh_find_route_index(dest_id);

    if (idx >= 0)
    {
        /* Update existing route if the new one is better (fewer hops or better signal) */
        if (hops < mesh_state.routes[idx].hops ||
            (hops == mesh_state.routes[idx].hops && rssi > mesh_state.routes[idx].rssi))
        {
            mesh_state.routes[idx].next_hop = next_hop;
            mesh_state.routes[idx].hops = hops;
            mesh_state.routes[idx].rssi = rssi;
            mesh_state.routes[idx].band = band;
            mesh_state.routes[idx].last_updated = platform_get_time_ms();
        }
    }
    else
    {
        /* Find an empty slot */
        for (int i = 0; i < MAX_ROUTE_ENTRIES; i++)
        {
            if (mesh_state.routes[i].dest_id == 0)
            {
                mesh_state.routes[i].dest_id = dest_id;
                mesh_state.routes[i].next_hop = next_hop;
                mesh_state.routes[i].hops = hops;
                mesh_state.routes[i].rssi = rssi;
                mesh_state.routes[i].band = band;
                mesh_state.routes[i].last_updated = platform_get_time_ms();
                return 0;
            }
        }

        /* Routing table is full - replace the oldest entry */
        uint32_t oldest_time = 0xFFFFFFFF;
        int oldest_idx = 0;

        for (int i = 0; i < MAX_ROUTE_ENTRIES; i++)
        {
            if (mesh_state.routes[i].last_updated < oldest_time)
            {
                oldest_time = mesh_state.routes[i].last_updated;
                oldest_idx = i;
            }
        }

        mesh_state.routes[oldest_idx].dest_id = dest_id;
        mesh_state.routes[oldest_idx].next_hop = next_hop;
        mesh_state.routes[oldest_idx].hops = hops;
        mesh_state.routes[oldest_idx].rssi = rssi;
        mesh_state.routes[oldest_idx].band = band;
        mesh_state.routes[oldest_idx].last_updated = platform_get_time_ms();
    }

    return 0;
}

/**
 * Find the index of a route in the routing table
 */
static int mesh_find_route_index(uint16_t dest_id)
{
    for (int i = 0; i < MAX_ROUTE_ENTRIES; i++)
    {
        if (mesh_state.routes[i].dest_id == dest_id)
        {
            return i;
        }
    }
    return -1; /* Not found */
}

/**
 * Add or update a neighbor in the neighbor table
 */
static int mesh_add_neighbor(uint16_t node_id, uint8_t band, int16_t rssi)
{
    if (node_id == 0 || node_id == mesh_state.our_node_id)
    {
        return -1;
    }

    /* Find existing neighbor */
    int idx = mesh_find_neighbor_index(node_id);

    if (idx >= 0)
    {
        /* Update existing neighbor */
        mesh_state.neighbors[idx].rssi[band] = rssi;
        mesh_state.neighbors[idx].bands |= (1 << band); /* Mark this band as supported */
        mesh_state.neighbors[idx].last_seen = platform_get_time_ms();
        mesh_state.neighbors[idx].is_active = 1;
    }
    else
    {
        /* Find an empty slot */
        for (int i = 0; i < MAX_NEIGHBORS; i++)
        {
            if (mesh_state.neighbors[i].node_id == 0)
            {
                mesh_state.neighbors[i].node_id = node_id;
                mesh_state.neighbors[i].bands = (1 << band); /* Mark only this band as known */
                mesh_state.neighbors[i].rssi[0] = -128;
                mesh_state.neighbors[i].rssi[1] = -128;
                mesh_state.neighbors[i].rssi[2] = -128;
                mesh_state.neighbors[i].rssi[band] = rssi;
                mesh_state.neighbors[i].last_seen = platform_get_time_ms();
                mesh_state.neighbors[i].battery_level = 0; /* Unknown */
                mesh_state.neighbors[i].is_active = 1;
                return 0;
            }
        }

        /* Neighbor table is full - replace the oldest entry */
        uint32_t oldest_time = 0xFFFFFFFF;
        int oldest_idx = 0;

        for (int i = 0; i < MAX_NEIGHBORS; i++)
        {
            if (mesh_state.neighbors[i].last_seen < oldest_time)
            {
                oldest_time = mesh_state.neighbors[i].last_seen;
                oldest_idx = i;
            }
        }

        mesh_state.neighbors[oldest_idx].node_id = node_id;
        mesh_state.neighbors[oldest_idx].bands = (1 << band);
        mesh_state.neighbors[oldest_idx].rssi[0] = -128;
        mesh_state.neighbors[oldest_idx].rssi[1] = -128;
        mesh_state.neighbors[oldest_idx].rssi[2] = -128;
        mesh_state.neighbors[oldest_idx].rssi[band] = rssi;
        mesh_state.neighbors[oldest_idx].last_seen = platform_get_time_ms();
        mesh_state.neighbors[oldest_idx].battery_level = 0;
        mesh_state.neighbors[oldest_idx].is_active = 1;
    }

    return 0;
}

/**
 * Find the index of a neighbor in the neighbor table
 */
static int mesh_find_neighbor_index(uint16_t node_id)
{
    for (int i = 0; i < MAX_NEIGHBORS; i++)
    {
        if (mesh_state.neighbors[i].node_id == node_id)
        {
            return i;
        }
    }
    return -1; /* Not found */
}

/**
 * Select the best band for transmission to a specific destination
 */
static int mesh_select_best_band(uint16_t dest_id)
{
    /* If this is a direct neighbor, use the band with best RSSI */
    int neighbor_idx = mesh_find_neighbor_index(dest_id);
    if (neighbor_idx >= 0 && mesh_state.neighbors[neighbor_idx].is_active)
    {
        /* Find best band for this neighbor */
        int8_t best_rssi = -128;
        uint8_t best_band = BAND_433MHZ; /* Default */

        for (int b = 0; b < 3; b++)
        {
            /* Check if this band is supported by the neighbor */
            if (mesh_state.neighbors[neighbor_idx].bands & (1 << b))
            {
                if (mesh_state.neighbors[neighbor_idx].rssi[b] > best_rssi)
                {
                    best_rssi = mesh_state.neighbors[neighbor_idx].rssi[b];
                    best_band = b;
                }
            }
        }

        return best_band;
    }

    /* If there's a route, use the band specified in the route */
    int route_idx = mesh_find_route_index(dest_id);
    if (route_idx >= 0)
    {
        return mesh_state.routes[route_idx].band;
    }

    /* No specific information - use band with best general performance */
    uint16_t scores[3] = {0};

    /* Calculate scores for each band */
    for (int b = 0; b < 3; b++)
    {
        /* Base score: successful transmissions */
        scores[b] = mesh_state.band_stats[b].tx_count * 10;

        /* Reduce score for errors */
        if (mesh_state.band_stats[b].error_count > 0)
        {
            scores[b] /= mesh_state.band_stats[b].error_count;
        }

        /* Factor in RSSI */
        int16_t rssi = mesh_state.band_stats[b].avg_rssi;
        if (rssi < -100)
        {
            scores[b] /= 2; /* Very weak signal */
        }
        else if (rssi > -70)
        {
            scores[b] *= 2; /* Strong signal */
        }

        /* Factor in SNR */
        int8_t snr = mesh_state.band_stats[b].avg_snr;
        if (snr > 10)
        {
            scores[b] *= 3; /* Excellent SNR */
        }
        else if (snr < 0)
        {
            scores[b] /= 2; /* Poor SNR */
        }
    }

    /* Find band with highest score */
    uint8_t best_band = BAND_433MHZ;
    uint16_t best_score = scores[BAND_433MHZ];

    for (int b = 1; b < 3; b++)
    {
        if (scores[b] > best_score)
        {
            best_score = scores[b];
            best_band = b;
        }
    }

    return best_band;
}

/**
 * Update band statistics with new measurements
 */
static int mesh_update_band_stats(uint8_t band, int16_t rssi, int8_t snr, uint8_t is_rx)
{
    if (band > BAND_915MHZ)
    {
        return -1;
    }

    /* Update appropriate counters */
    if (is_rx)
    {
        mesh_state.band_stats[band].rx_count++;

        /* Update signal stats with exponential moving average */
        if (mesh_state.band_stats[band].avg_rssi == -100)
        {
            /* First measurement */
            mesh_state.band_stats[band].avg_rssi = rssi;
            mesh_state.band_stats[band].avg_snr = snr;
        }
        else
        {
            /* EMA with 0.2 alpha */
            mesh_state.band_stats[band].avg_rssi =
                (mesh_state.band_stats[band].avg_rssi * 4 + rssi) / 5;
            mesh_state.band_stats[band].avg_snr =
                (mesh_state.band_stats[band].avg_snr * 4 + snr) / 5;
        }
    }
    else
    {
        mesh_state.band_stats[band].tx_count++;
    }

    return 0;
}

/**
 * Perform periodic maintenance tasks
 */
static void mesh_periodic_tasks(void)
{
    uint32_t current_time = platform_get_time_ms();

    /* Send periodic beacons */
    if (current_time - mesh_state.last_beacon_time > BEACON_INTERVAL_MS)
    {
        mesh_send_beacon();
    }

    /* Periodically clean up routing table (every 5 minutes) */
    if (current_time - mesh_state.last_route_cleanup > 300000)
    {
        mesh_prune_routes();
        mesh_state.last_route_cleanup = current_time;
    }

    /* Periodically measure noise floor (every 10 minutes) */
    static uint32_t last_noise_measurement = 0;
    if (current_time - last_noise_measurement > 600000)
    {
        /* Measure noise floor on all bands */
        for (int b = 0; b < 3; b++)
        {
            /* Skip if not the current band (would require switching) */
            if (b == mesh_state.active_band)
            {
                int16_t noise = radio_measure_noise_floor();
                if (noise < 0)
                {
                    /* Valid measurement (in dBm) - convert to positive noise floor value */
                    mesh_state.band_stats[b].noise_floor = -noise;
                }
            }
        }

        last_noise_measurement = current_time;
    }
}