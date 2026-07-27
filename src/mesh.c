#include "mesh.h"
#include "packet.h"
#include "radio.h"
#include "radio_config.h"
#include "security.h"
#include "platform.h"
#include <string.h>

/* Limits and timing */
#define MAX_NEIGHBORS         32
/* ROUTE_TIMEOUT_MS is defined in mesh.h; do not re-define here to avoid constraint violation. */
#define NEIGHBOR_TIMEOUT_MS   300000UL   /* 5 minutes */
#define BEACON_INTERVAL_MS    60000UL    /* Regular beacons */
#define DISCOVERY_BEACONS     3
#define DISCOVERY_DELAY_MS    500

/* Route entry states */
#define ROUTE_INVALID   0
#define ROUTE_DIRECT    1
#define ROUTE_INDIRECT  2

/* Network-level shared PSK for management/beacons MUST be provisioned identically on all nodes in the same mesh.
   On real hardware this is loaded from configuration/flash; here we keep a configurable default for demo/testing. */
#define MESH_NETWORK_PSK "MERIDIAN_DEFAULT_PSK_V1" /* Replace with actual provisioned key per deployment */

/**
 * Derives the network encryption key from the configured pre-shared key.
 *
 * @param out Buffer that receives the derived network key.
 */
static void derive_network_key_from_psk(uint8_t out[SYMMETRIC_KEY_LENGTH]) {
    crypto_generichash(out, SYMMETRIC_KEY_LENGTH, (uint8_t*)MESH_NETWORK_PSK, strlen(MESH_NETWORK_PSK), NULL, 0);
}

/* Radio callbacks */
static void mesh_rx_handler(uint8_t* data, size_t len, int16_t rssi, int8_t snr);
static void mesh_tx_handler(void);
static void mesh_error_handler(uint16_t error);

/* Group management helpers called from examples/app-level code */
int mesh_send_group_join_invite(uint16_t leader_id, uint16_t member_id, uint16_t group_id);
int mesh_broadcast_group_chat(uint16_t group_id, const uint8_t* payload, size_t len);

/* Module state */
static struct {
    uint16_t our_node_id;
    route_entry_t routes[MAX_ROUTE_ENTRIES];
    neighbor_t neighbors[MAX_NEIGHBORS];
    uint32_t last_beacon_time;
    uint32_t last_route_cleanup;
    uint8_t active_band;
    uint8_t discovery_mode;

    /* Network-level shared key derived from a common PSK (same on all nodes in mesh) */
    uint8_t network_key[SYMMETRIC_KEY_LENGTH];

    /* Optional application callback for received packets after decryption and core processing. */
    void (*app_rx_callback)(const packet_t* packet, int16_t rssi, int8_t snr);
} mesh_state;

/* Forward declarations */
static int mesh_send_packet_internal(packet_t* packet, const uint8_t* session_key);
static int mesh_add_route(uint16_t dest_id, uint16_t next_hop, uint8_t hops, int8_t rssi, uint8_t band);
static int mesh_find_route_index(uint16_t dest_id);
static int mesh_add_neighbor(uint16_t node_id, uint8_t band, int16_t rssi);
static int mesh_find_neighbor_index(uint16_t node_id);

/**
 * Initializes the mesh state, radio, network key, and initial beacon transmission.
 *
 * @param our_node_id Identifier assigned to this node.
 * @return 0 on success, or -1 if radio initialization fails.
 */

int mesh_init(uint16_t our_node_id) {
    memset(&mesh_state, 0, sizeof(mesh_state));
    mesh_state.our_node_id = our_node_id;
    mesh_state.active_band = BAND_433MHZ;

    for (int i = 0; i < MAX_ROUTE_ENTRIES; i++) {
        mesh_state.routes[i].dest_id = 0;
    }
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        mesh_state.neighbors[i].node_id = 0;
    }

    /* Initialize radio config */
    radio_config_t config = BAND_CONFIG_433MHZ;
    if (radio_init(&config) != 0) {
        return -1;
    }

    radio_set_rx_callback(mesh_rx_handler);
    radio_set_tx_callback(mesh_tx_handler);
    radio_set_error_callback(mesh_error_handler);
    radio_set_rx(0); /* Continuous receive */

    /* Derive a consistent network key from the shared PSK so all nodes in the same mesh can communicate. */
    derive_network_key_from_psk(mesh_state.network_key);

    /* Send initial beacon */
    mesh_send_beacon();

    return 0;
}

/**
 * Sets the callback for application-level packets after decryption and core processing.
 *
 * @param callback Function invoked with each processed application-level packet.
 * @return 0 on success.
 */
int mesh_set_rx_callback(void (*callback)(const packet_t* packet, int16_t rssi, int8_t snr)) {
    /* Store callback for application-level packets after decryption and core processing. */
    mesh_state.app_rx_callback = callback;
    return 0;
}

/**
 * Processes a decrypted packet, updating routing state and dispatching it by type.
 *
 * @param packet Decrypted packet to process.
 * @param from_node Relay node that forwarded the packet, or 0 for a direct link.
 * @param rssi Received signal strength indication.
 * @param snr Received signal-to-noise ratio.
 * @return 0 on success, or -1 if packet is null or contains an incomplete handshake payload.
 */

int mesh_process_packet(const packet_t* packet, uint16_t from_node, int16_t rssi, int8_t snr) {
    if (!packet) return -1;

    /* Routing update: if from_node is zero this was a direct link; otherwise it's via that relay. */
    uint8_t band = packet->header.band_info & 0x03;
    mesh_update_routing(packet->header.source, from_node, rssi, band);

    /* Process by type */
    switch (packet->header.type) {
        case PACKET_TYPE_BEACON: {
            uint8_t supported_bands = 0x07;   /* Default: all three bands */
            uint8_t battery_level = 100;      /* Placeholder */

            if (packet->payload_len >= 2) {
                supported_bands = packet->payload[0];
                battery_level   = packet->payload[1];
            }

            int nidx = mesh_find_neighbor_index(packet->header.source);
            if (nidx >= 0) {
                mesh_state.neighbors[nidx].bands         = supported_bands;
                mesh_state.neighbors[nidx].battery_level = battery_level;
                /* Only index 0 is valid for band_info & 0x03 since neighbor.rssi has 3 elements. */
                int safe_band = (band < 3) ? (int)band : 0;
                mesh_state.neighbors[nidx].rssi[safe_band] = (int8_t)rssi;
                mesh_state.neighbors[nidx].last_seen     = platform_get_time_ms();
                mesh_state.neighbors[nidx].is_active     = 1;
            } else {
                mesh_add_neighbor(packet->header.source, band, rssi);
            }

            /* Discovery-mode response: schedule beacon via deferred send to avoid blocking in ISR context */
            if (mesh_state.discovery_mode && packet->payload_len >= 3 && packet->payload[2]) {
                mesh_state.last_beacon_time = 0; /* Force immediate beacon on next periodic tick */
            }
            break;
        }

        case PACKET_TYPE_HANDSHAKE: {
            /* Payload is already decrypted in-place by mesh_rx_handler before dispatch here. */
            if (packet->payload_len < sizeof(handshake_message_t)) {
                return -1;
            }

            handshake_message_t msg;
            memcpy(&msg, packet->payload, sizeof(msg));

            handshake_message_t response;
            int h = security_process_handshake(&msg, mesh_state.our_node_id, &response);
            if (h == 0 && response.type != 0) {
                /* Send encrypted handshake response */
                packet_t rsp_pkt;
                if (packet_create(&rsp_pkt, msg.initiator_id, PACKET_TYPE_HANDSHAKE,
                                  (uint8_t*)&response, sizeof(response)) == 0) {
                    mesh_send_packet_internal(&rsp_pkt, mesh_state.network_key);
                }
            }
            break;
        }

        case PACKET_TYPE_GROUP_JOIN: {
            /* Payload is already decrypted in-place by mesh_rx_handler using the pairwise session key. */
            uint16_t sender_id = packet->header.source;
            if (packet->payload_len < sizeof(group_join_payload_t)) {
                break; /* Too small */
            }

            group_join_payload_t join;
            memcpy(&join, packet->payload, sizeof(join));

            /* Store the group key: this node is now a member of that group. */
            int rc = security_set_group_key(join.group_id, join.group_key, sender_id);
            if (rc != 0) {
                platform_log(LOG_LEVEL_ERROR, "GROUP_JOIN failed to store key for group %u",
                             (unsigned)join.group_id);
            } else {
                platform_log(LOG_LEVEL_INFO, "Joined group %u from leader %u (epoch=%u)",
                             (unsigned)join.group_id, sender_id, join.epoch);
            }

            break;
        }

        default:
            /* Application-level packet: invoke callback if registered */
            if (mesh_state.app_rx_callback) {
                mesh_state.app_rx_callback(packet, rssi, snr);
            }
            break;
    }

    return 0;
}

/**
 * Encrypts and transmits a packet using the appropriate network or session key.
 *
 * @param packet Packet to encrypt and transmit.
 * @returns The transmission result, or `-1` if `packet` is null, or `-3` if a session key cannot be established.
 */

int mesh_send_packet(packet_t* packet) {
    if (!packet) return -1;

    uint8_t session_key_buf[SYMMETRIC_KEY_LENGTH];

    /* Broadcast/management: use network key directly */
    if (packet->header.destination == BROADCAST_ADDR) {
        memcpy(session_key_buf, mesh_state.network_key, SYMMETRIC_KEY_LENGTH);
    } else {
        /* Try to find pairwise session key for destination */
        int rc = security_get_session_key(packet->header.destination, session_key_buf);
        if (rc != 0) {
            /* No session yet: attempt handshake with destination before sending.
             * In real async systems you'd queue and retry later instead of blocking here. */
            uint8_t our_pub[PUBLIC_KEY_LENGTH];
            security_get_identity_public_key(our_pub);

            handshake_message_t hello;
            memset(&hello, 0, sizeof(hello));
            hello.type          = HANDSHAKE_TYPE_HELLO;
            hello.initiator_id  = mesh_state.our_node_id;
            hello.responder_id  = packet->header.destination;
            memcpy(hello.public_key, our_pub, PUBLIC_KEY_LENGTH);

            /* Send handshake request first */
            packet_t hpkt;
            if (packet_create(&hpkt, BROADCAST_ADDR, PACKET_TYPE_HANDSHAKE,
                              (uint8_t*)&hello, sizeof(hello)) == 0) {
                mesh_send_packet_internal(&hpkt, mesh_state.network_key);
            }

            /* Wait briefly for response (blocking; only OK in sim/test on Linux). */
            platform_delay_ms(100);

            rc = security_get_session_key(packet->header.destination, session_key_buf);
            if (rc != 0) {
                return -3; /* No route/session to destination */
            }
        }
    }

    /* Pick band */
    uint8_t best_band = mesh_state.active_band;
    if (packet->header.destination != BROADCAST_ADDR) {
        uint16_t next_hop = mesh_find_next_hop(packet->header.destination, &best_band);
        (void)next_hop; /* Already handled by routing below */
    }

    if (best_band != mesh_state.active_band) {
        radio_switch_band(best_band);
        mesh_state.active_band = best_band;
    }

    packet->header.band_info = best_band & 0x03;
    return mesh_send_packet_internal(packet, session_key_buf);
}

/**
 * Encrypts, serializes, and transmits a packet.
 *
 * @param packet Packet to transmit.
 * @param key Encryption key.
 * @return `0` or a radio transmission result on success, `-1` if encryption
 *         fails, or `-2` if serialization fails.
 */
static int mesh_send_packet_internal(packet_t* packet, const uint8_t* key) {
    if (packet_encrypt(packet, key) != 0) {
        return -1;
    }

    uint8_t buf[MAX_PACKET_SIZE];
    int len = packet_serialize(packet, buf, sizeof(buf));
    if (len <= 0) return -2;

    return radio_transmit(buf, (size_t)len, 2000);
}

/**
 * Finds the next hop and radio band for reaching a destination node.
 *
 * @param dest_id Destination node identifier.
 * @param best_band Output pointer receiving the selected radio band.
 * @return The next-hop node identifier, or 0 if no route is available.
 */

uint16_t mesh_find_next_hop(uint16_t dest_id, uint8_t* best_band) {
    if (dest_id == 0 || dest_id == mesh_state.our_node_id) {
        return 0;
    }

    /* Direct neighbor? */
    int nidx = mesh_find_neighbor_index(dest_id);
    if (nidx >= 0 && mesh_state.neighbors[nidx].is_active) {
        int8_t best_rssi = -128;
        *best_band = BAND_433MHZ;
        for (int b = 0; b < 3; b++) {
            if ((mesh_state.neighbors[nidx].bands & (1 << b)) &&
                mesh_state.neighbors[nidx].rssi[b] > best_rssi) {
                best_rssi = mesh_state.neighbors[nidx].rssi[b];
                *best_band = b;
            }
        }
        return dest_id;
    }

    /* Via route table */
    int ridx = mesh_find_route_index(dest_id);
    if (ridx >= 0) {
        *best_band = mesh_state.routes[ridx].band;
        return mesh_state.routes[ridx].next_hop;
    }

    return 0; /* No route */
}

/**
 * Updates neighbor and route information for a node observed directly or through a relay.
 *
 * @param source Node whose route information is being updated.
 * @param from_node Relay node through which the source was observed, or 0 for a direct link.
 * @param rssi Received signal strength for the observation.
 * @param band Radio band used for the observation.
 * @returns 0 on success, or -1 if source is zero or identifies this node.
 */
int mesh_update_routing(uint16_t source, uint16_t from_node, int16_t rssi, uint8_t band) {
    if (source == 0 || source == mesh_state.our_node_id) return -1;

    int safe_band = (band < 3) ? (int)band : 0; /* clamp to valid range for neighbor.rssi[3] */

    if (from_node == 0) {
        /* Direct link: heard directly from the source */
        mesh_add_neighbor(source, band, rssi);
        mesh_add_route(source, source, 1, safe_band ? -90 : rssi, band);
    } else {
        /* Indirect route via 'from_node': update both neighbor and route table.
         * Also keep a neighbor entry for the relay node itself. */
        mesh_add_neighbor(from_node, band, rssi);

        int via_idx = mesh_find_route_index(from_node);
        if (via_idx >= 0) {
            uint8_t hops = mesh_state.routes[via_idx].hops + 1;
            if (hops <= MAX_TTL) {
                mesh_add_route(source, from_node, hops, rssi, band);
            }
        }
    }

    return 0;
}

/**
 * Broadcasts discovery beacons and returns the number of active neighbors found.
 *
 * @return The number of active neighbors.
 */
int mesh_discover(void) {
    mesh_state.discovery_mode = 1;

    for (int i = 0; i < DISCOVERY_BEACONS; i++) {
        uint8_t payload[] = {0x07, 100, 1, 0}; /* bands, battery, discovery=1 */
        packet_t pkt;
        packet_create(&pkt, BROADCAST_ADDR, PACKET_TYPE_BEACON, payload, sizeof(payload));
        pkt.header.ttl = 1;
        pkt.header.band_info = mesh_state.active_band & 0x03;

        /* Encrypt beacon with network key */
        packet_encrypt(&pkt, mesh_state.network_key);

        uint8_t buf[MAX_PACKET_SIZE];
        int len = packet_serialize(&pkt, buf, sizeof(buf));
        if (len > 0) {
            radio_transmit(buf, (size_t)len, 1000);
        }

        platform_delay_ms(DISCOVERY_DELAY_MS);
    }

    mesh_state.discovery_mode = 0;
    return mesh_count_neighbors();
}

/**
 * Broadcasts a packet to all nodes using the network key.
 *
 * @param type Packet type.
 * @param payload Data to broadcast.
 * @param payload_len Length of the payload in bytes.
 * @param ttl Maximum number of hops.
 * @return Transmission result; -1 if the payload is invalid, or -2 if packet creation fails.
 */
int mesh_broadcast(uint8_t type, const uint8_t* payload, size_t payload_len, uint8_t ttl) {
    if (!payload || payload_len > MAX_PAYLOAD_SIZE) return -1;

    packet_t pkt;
    if (packet_create(&pkt, BROADCAST_ADDR, type, payload, payload_len) != 0) {
        return -2;
    }

    pkt.header.ttl = ttl;
    pkt.header.band_info = mesh_state.active_band & 0x03;

    /* Broadcasts encrypted with network key */
    return mesh_send_packet_internal(&pkt, mesh_state.network_key);
}

/**
 * Retrieves the recorded information for a neighboring node.
 * @param node_id Identifier of the neighbor to retrieve.
 * @param neighbor Destination for the neighbor information.
 * @return 0 if the neighbor is found, 1 if it is not found, or -1 if neighbor is null.
 */
int mesh_get_neighbor(uint16_t node_id, neighbor_t* neighbor) {
    if (!neighbor) return -1;
    int idx = mesh_find_neighbor_index(node_id);
    if (idx < 0) return 1; /* Not found */
    *neighbor = mesh_state.neighbors[idx];
    return 0;
}

/**
 * Updates a neighbor's signal information for the specified band.
 *
 * @param node_id Neighbor node identifier.
 * @param band Radio band used to reach the neighbor.
 * @param rssi Received signal strength indicator.
 * @return 0 on success, or -1 if the node identifier is invalid.
 */
int mesh_update_neighbor(uint16_t node_id, uint8_t band, int16_t rssi) {
    return mesh_add_neighbor(node_id, band, rssi);
}

/**
 * Counts neighbors that have been seen within the neighbor timeout period.
 *
 * @return The number of active neighbors.
 */
int mesh_count_neighbors(void) {
    int count = 0;
    uint32_t now = platform_get_time_ms();
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (mesh_state.neighbors[i].node_id != 0 &&
            (now - mesh_state.neighbors[i].last_seen) < NEIGHBOR_TIMEOUT_MS) {
            count++;
        }
    }
    return count;
}

/**
 * Removes routes that have exceeded the route timeout.
 *
 * @return The number of routes removed.
 */
int mesh_prune_routes(void) {
    int pruned = 0;
    uint32_t now = platform_get_time_ms();
    for (int i = 0; i < MAX_ROUTE_ENTRIES; i++) {
        if (mesh_state.routes[i].dest_id != 0 &&
            (now - mesh_state.routes[i].last_updated) > ROUTE_TIMEOUT_MS) {
            mesh_state.routes[i].dest_id = 0; /* Invalidate */
            pruned++;
        }
    }
    return pruned;
}

/**
 * Sends a broadcast beacon announcing this node's supported bands and battery level.
 *
 * @return 0 or a radio transmission status on success, -1 if the beacon packet cannot be created.
 */
int mesh_send_beacon(void) {
    uint8_t payload[] = {0x07, 100}; /* bands mask, battery level */

    packet_t pkt;
    if (packet_create(&pkt, BROADCAST_ADDR, PACKET_TYPE_BEACON, payload, sizeof(payload)) != 0) {
        return -1;
    }

    pkt.header.ttl = 1;
    pkt.header.band_info = mesh_state.active_band & 0x03;
    return mesh_send_packet_internal(&pkt, mesh_state.network_key);
}

/**
 * Adds or updates a route entry for a destination node.
 *
 * @param dest_id Destination node identifier.
 * @param next_hop Next node used to reach the destination.
 * @param hops Number of hops to the destination.
 * @param rssi Link signal strength for the route.
 * @param band Radio band used by the route.
 * @return Always 0.
 */

static int mesh_add_route(uint16_t dest_id, uint16_t next_hop, uint8_t hops,
                          int8_t rssi, uint8_t band) {
    int idx = mesh_find_route_index(dest_id);
    if (idx < 0) {
        /* Find empty slot */
        for (int i = 0; i < MAX_ROUTE_ENTRIES; i++) {
            if (mesh_state.routes[i].dest_id == 0) {
                idx = i;
                break;
            }
        }
    }

    if (idx >= 0) {
        mesh_state.routes[idx].dest_id      = dest_id;
        mesh_state.routes[idx].next_hop     = next_hop;
        mesh_state.routes[idx].hops         = hops;
        mesh_state.routes[idx].rssi         = rssi;
        mesh_state.routes[idx].band         = band;
        mesh_state.routes[idx].last_updated = platform_get_time_ms();
    }

    return 0;
}

/**
 * Finds the route-table entry for a destination node.
 * @param dest_id Destination node identifier.
 * @return The matching route-table index, or -1 if no entry exists.
 */
static int mesh_find_route_index(uint16_t dest_id) {
    for (int i = 0; i < MAX_ROUTE_ENTRIES; i++) {
        if (mesh_state.routes[i].dest_id == dest_id) {
            return i;
        }
    }
    return -1;
}

/**
 * Adds or updates a neighbor entry with its signal strength and last-seen time.
 *
 * @param node_id Neighbor node identifier.
 * @param band Band on which the neighbor was observed.
 * @param rssi Received signal strength indicator.
 * @return 0 on completion, or -1 if the node identifier is invalid.
 */
static int mesh_add_neighbor(uint16_t node_id, uint8_t band, int16_t rssi) {
    if (node_id == 0 || node_id == mesh_state.our_node_id) return -1;

    int idx = mesh_find_neighbor_index(node_id);
    if (idx < 0) {
        for (int i = 0; i < MAX_NEIGHBORS; i++) {
            if (mesh_state.neighbors[i].node_id == 0) {
                idx = i;
                break;
            }
        }
    }

    int safe_band = (band < 3) ? (int)band : 0; /* clamp to valid range */
    if (idx >= 0) {
        mesh_state.neighbors[idx].node_id   = node_id;
        mesh_state.neighbors[idx].bands     = 0x07; /* Assume all bands until proven otherwise */
        mesh_state.neighbors[idx].rssi[safe_band] = (int8_t)rssi;
        mesh_state.neighbors[idx].last_seen = platform_get_time_ms();
        mesh_state.neighbors[idx].is_active = 1;
    }

    return 0;
}

/**
 * Finds the neighbor table entry for a node.
 *
 * @param node_id Node identifier to search for.
 * @return The neighbor table index, or -1 if the node is not found.
 */
static int mesh_find_neighbor_index(uint16_t node_id) {
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (mesh_state.neighbors[i].node_id == node_id) {
            return i;
        }
    }
    return -1;
}

/**
 * Processes a received radio frame by deserializing, decrypting, and dispatching its packet.
 *
 * @param data Received frame data.
 * @param len Length of the received frame in bytes.
 * @param rssi Received signal strength.
 * @param snr Signal-to-noise ratio.
 */

static void mesh_rx_handler(uint8_t* data, size_t len, int16_t rssi, int8_t snr) {
    packet_t pkt;
    if (packet_deserialize(data, len, &pkt) != 0) return;

    /* Determine which key to use for decryption. */
    const uint8_t* decrypt_key = NULL;

    switch (pkt.header.type) {
        case PACKET_TYPE_BEACON:
        case PACKET_TYPE_HANDSHAKE:
            /* Management/beacons: encrypted with the network key */
            decrypt_key = mesh_state.network_key;
            break;

        default:
            {
                uint8_t key[SYMMETRIC_KEY_LENGTH];
                int rc = security_get_session_key(pkt.header.source, key);
                if (rc == 0) {
                    /* Use a local copy on stack for decrypt pointer */
                    static uint8_t temp_key[SYMMETRIC_KEY_LENGTH];
                    memcpy(temp_key, key, SYMMETRIC_KEY_LENGTH);
                    decrypt_key = temp_key;
                } else {
                    return; /* Unknown source without session -> drop */
                }
            }
            break;
    }

    if (!decrypt_key) {
        return; /* Cannot determine key for this packet type */
    }

    /* Decrypt payload in-place (already authenticated via AEAD). */
    if (packet_decrypt(&pkt, decrypt_key) != 0) {
        return; /* Auth failed or bad inputs */
    }

    /* For direct-receive packets from radio callback, from_node is zero. */
    int handled = packet_handle(&pkt, 0);
    if (handled >= 0) {
        mesh_process_packet(&pkt, 0, rssi, snr);
    }
}

static void mesh_tx_handler(void) {
    /* Post-transmission handling; no-op for now */
}

/**
 * Logs a radio error code at warning level.
 *
 * @param error Radio error code.
 */
static void mesh_error_handler(uint16_t error) {
    platform_log(LOG_LEVEL_WARNING, "Radio error: 0x%04X", error);
}

/**
 * Sends a group-join invitation containing the group's shared key to a member.
 *
 * @param leader_id Node ID of the group leader.
 * @param member_id Node ID of the member receiving the invitation.
 * @param group_id Identifier of the group to join.
 * @return `0` or a non-negative transmission result on success; `-1` for invalid identifiers, `-2` if the group key cannot be created, `-3` if no session is established with the member, or `-4` if the invitation packet cannot be created.
 */

int mesh_send_group_join_invite(uint16_t leader_id, uint16_t member_id, uint16_t group_id) {
    if (member_id == 0 || group_id == 0) {
        return -1; /* Invalid params */
    }

    /* Retrieve or create the shared group key on the leader. */
    uint8_t group_key[SYMMETRIC_KEY_LENGTH];
    int rc = security_get_group_key(group_id, group_key);
    if (rc != 0) {
        /* Leader does not yet have this group: generate a new PSK for it */
        randombytes_buf(group_key, SYMMETRIC_KEY_LENGTH);
        rc = security_set_group_key(group_id, group_key, leader_id);
        if (rc != 0) {
            return -2; /* Failed to create group key */
        }
    }

    /* Ensure pairwise session exists with the member node. */
    uint8_t sess_key[SYMMETRIC_KEY_LENGTH];
    rc = security_get_session_key(member_id, sess_key);
    if (rc != 0) {
        /* Trigger a handshake first by sending HELLO broadcasted for this member */
        uint8_t our_pub[PUBLIC_KEY_LENGTH];
        security_get_identity_public_key(our_pub);

        handshake_message_t hello;
        memset(&hello, 0, sizeof(hello));
        hello.type          = HANDSHAKE_TYPE_HELLO;
        hello.initiator_id  = leader_id;
        hello.responder_id  = member_id;
        memcpy(hello.public_key, our_pub, PUBLIC_KEY_LENGTH);

        packet_t hpkt;
        if (packet_create(&hpkt, BROADCAST_ADDR, PACKET_TYPE_HANDSHAKE,
                          (uint8_t*)&hello, sizeof(hello)) == 0) {
            mesh_send_packet_internal(&hpkt, mesh_state.network_key);
        }

        platform_delay_ms(100); /* Wait for response in sim; real impl would queue/retry */

        rc = security_get_session_key(member_id, sess_key);
        if (rc != 0) {
            return -3; /* No session with member after handshake attempt */
        }
    }

    /* Prepare GROUP_JOIN payload encrypted under pairwise session key */
    group_join_payload_t join;
    join.group_id = group_id;
    join.epoch    = 1; /* V1; bump for future rotations */
    memcpy(join.group_key, group_key, SYMMETRIC_KEY_LENGTH);

    packet_t pkt;
    if (packet_create(&pkt, member_id, PACKET_TYPE_GROUP_JOIN,
                      (uint8_t*)&join, sizeof(join)) != 0) {
        return -4;
    }

    rc = mesh_send_packet_internal(&pkt, sess_key);

    sodium_memzero(sess_key, sizeof(sess_key));
    return rc;
}

/**
 * Broadcasts a group chat message to all nodes within the mesh.
 *
 * @param group_id Group whose shared key encrypts the message.
 * @param payload Message data to broadcast.
 * @param len Length of the message data in bytes.
 * @return `0` or a radio transmission result on success; `-1` for invalid arguments,
 *         `-2` if the group key is unavailable, or `-3` if packet creation fails.
 */
int mesh_broadcast_group_chat(uint16_t group_id, const uint8_t* payload, size_t len) {
    if (!payload || len > MAX_PAYLOAD_SIZE || group_id == 0) {
        return -1;
    }

    /* Get the shared key for this group */
    uint8_t group_key[SYMMETRIC_KEY_LENGTH];
    int rc = security_get_group_key(group_id, group_key);
    if (rc != 0) {
        return -2; /* Not a member of this group */
    }

    packet_t pkt;
    if (packet_create(&pkt, BROADCAST_ADDR, PACKET_TYPE_GROUP_CHAT, payload, len) != 0) {
        return -3;
    }

    /* Encrypt with group key and broadcast */
    pkt.header.ttl = MAX_TTL; /* Propagate throughout the mesh */
    return mesh_send_packet_internal(&pkt, group_key);
}
