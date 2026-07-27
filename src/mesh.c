#include "mesh.h"
#include "packet.h"
#include "radio.h"
#include "radio_config.h"
#include "security.h"
#include "platform.h"
#include <string.h>

/* Limits and timing */
#define MAX_NEIGHBORS         32
#define ROUTE_TIMEOUT_MS      600000UL   /* 10 minutes */
#define NEIGHBOR_TIMEOUT_MS   300000UL   /* 5 minutes */
#define BEACON_INTERVAL_MS    60000UL    /* Regular beacons */
#define DISCOVERY_BEACONS     3
#define DISCOVERY_DELAY_MS    500

/* Route entry states */
#define ROUTE_INVALID   0
#define ROUTE_DIRECT    1
#define ROUTE_INDIRECT  2

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

    /* Network-level shared key (fallback for beacons/management if needed) */
    uint8_t network_key[SYMMETRIC_KEY_LENGTH];
} mesh_state;

/* Forward declarations */
static int mesh_send_packet_internal(packet_t* packet, const uint8_t* session_key);
static int mesh_add_route(uint16_t dest_id, uint16_t next_hop, uint8_t hops, int8_t rssi, uint8_t band);
static int mesh_find_route_index(uint16_t dest_id);
static int mesh_add_neighbor(uint16_t node_id, uint8_t band, int16_t rssi);
static int mesh_find_neighbor_index(uint16_t node_id);

/* ============================================================================
 * Initialization
 * ============================================================================ */

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

    /* Generate a local network key for management/broadcast packets.
     * In production this would be provisioned via PSK or derived from mesh credentials. */
    randombytes_buf(mesh_state.network_key, SYMMETRIC_KEY_LENGTH);

    /* Send initial beacon */
    mesh_send_beacon();

    return 0;
}

int mesh_set_rx_callback(void (*callback)(const packet_t* packet, int16_t rssi, int8_t snr)) {
    /* For now: we handle this via internal processing. Future extensibility hook. */
    (void)callback;
    return 0;
}

/* ============================================================================
 * Receive path: decrypt + process by type (beacon/handshake/data)
 * ============================================================================ */

int mesh_process_packet(const packet_t* packet, int16_t rssi, int8_t snr) {
    if (!packet) return -1;

    uint8_t band = packet->header.band_info & 0x03;
    mesh_update_routing(packet->header.source, 0, (int)rssi, band);

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
                mesh_state.neighbors[nidx].rssi[band]    = (int8_t)rssi;
                mesh_state.neighbors[nidx].last_seen     = platform_get_time_ms();
                mesh_state.neighbors[nidx].is_active     = 1;
            } else {
                mesh_add_neighbor(packet->header.source, band, rssi);
            }

            /* Discovery-mode response */
            if (mesh_state.discovery_mode && packet->payload_len >= 3 && packet->payload[2]) {
                platform_delay_ms(50 + (mesh_state.our_node_id % 50));
                mesh_send_beacon();
            }
            break;
        }

        case PACKET_TYPE_HANDSHAKE: {
            /* Decrypt handshake payload using network key first to authenticate source */
            uint8_t plain[sizeof(handshake_message_t)];
            secure_nonce_t nonce;
            memset(&nonce, 0, sizeof(nonce));
            memcpy(&nonce.value, &packet->header.nonce_value, 8);

            int dec = security_decrypt(mesh_state.network_key, &nonce,
                                       packet->payload, packet->payload_len,
                                       (uint8_t*)&packet->header, sizeof(packet_header_t),
                                       packet->tag, plain);

            if (dec < 0 || (size_t)dec < sizeof(handshake_message_t)) {
                /* Can't decrypt handshake -> drop */
                return -1;
            }

            handshake_message_t msg;
            memcpy(&msg, plain, sizeof(msg));

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
            /* GROUP_JOIN is encrypted under the pairwise session key between leader and this node. */
            uint16_t sender_id = packet->header.source;

            uint8_t sess_key[SYMMETRIC_KEY_LENGTH];
            int rc = security_get_session_key(sender_id, sess_key);
            if (rc != 0) {
                /* No session with sender: ignore this invite */
                break;
            }

            uint8_t plain[MAX_PAYLOAD_SIZE];
            secure_nonce_t nonce;
            memset(&nonce, 0, sizeof(nonce));
            memcpy(&nonce.value, &packet->header.nonce_value, 8);

            int dec = security_decrypt(sess_key, &nonce,
                                       packet->payload, packet->payload_len,
                                       (uint8_t*)&packet->header, sizeof(packet_header_t),
                                       packet->tag, plain);
            if (dec < 0 || (size_t)dec < sizeof(group_join_payload_t)) {
                break; /* Can't decrypt or too small */
            }

            group_join_payload_t join;
            memcpy(&join, plain, sizeof(join));

            /* Store the group key: this node is now a member of that group. */
            rc = security_set_group_key(join.group_id, join.group_key, sender_id);
            if (rc != 0) {
                platform_log(LOG_LEVEL_ERROR, "GROUP_JOIN failed to store key for group %u",
                             (unsigned)join.group_id);
            } else {
                platform_log(LOG_LEVEL_INFO, "Joined group %u from leader %u (epoch=%u)",
                             (unsigned)join.group_id, sender_id, join.epoch);
            }

            sodium_memzero(sess_key, sizeof(sess_key));
            break;
        }

        default:
            /* Application-level packet or unknown type */
            break;
    }

    return 0;
}

/* ============================================================================
 * Transmit path: per-destination session key lookup + encryption
 * ============================================================================ */

int mesh_send_packet(packet_t* packet) {
    if (!packet) return -1;

    uint8_t* session_key = NULL;

    /* Broadcast/management: use network key directly */
    if (packet->header.destination == BROADCAST_ADDR) {
        session_key = mesh_state.network_key;
    } else {
        /* Try to find pairwise session key for destination */
        uint8_t tmp_key[SYMMETRIC_KEY_LENGTH];
        int rc = security_get_session_key(packet->header.destination, tmp_key);
        if (rc == 0) {
            /* Temp workaround: we need pointer; copy into fixed buffer. */
            static uint8_t cached_keys[64][SYMMETRIC_KEY_LENGTH];
            static uint16_t last_used[64] = {0};
            static uint8_t slot_idx = 0;

            /* Find matching entry to reuse */
            int found = -1;
            for (int i = 0; i < 64; i++) {
                if (last_used[i] == packet->header.destination) {
                    found = i;
                    break;
                }
            }
            if (found < 0) {
                slot_idx = slot_idx % 64;
                last_used[slot_idx] = packet->header.destination;
                memcpy(cached_keys[slot_idx], tmp_key, SYMMETRIC_KEY_LENGTH);
                found = slot_idx++;
            }
            session_key = cached_keys[found];
        } else {
            /* No session yet: attempt handshake with destination before sending */
            uint8_t eph_pub[PUBLIC_KEY_LENGTH], eph_priv[PRIVATE_KEY_LENGTH];
            crypto_box_keypair(eph_pub, eph_priv);

            handshake_message_t hello;
            memset(&hello, 0, sizeof(hello));
            hello.type          = HANDSHAKE_TYPE_HELLO;
            hello.initiator_id  = mesh_state.our_node_id;
            hello.responder_id  = packet->header.destination;
            memcpy(hello.public_key, eph_pub, PUBLIC_KEY_LENGTH);

            /* Send handshake request first */
            packet_t hpkt;
            if (packet_create(&hpkt, BROADCAST_ADDR, PACKET_TYPE_HANDSHAKE,
                              (uint8_t*)&hello, sizeof(hello)) == 0) {
                mesh_send_packet_internal(&hpkt, mesh_state.network_key);
            }

            /* Wait briefly for response (in real async system, you'd queue and retry later) */
            platform_delay_ms(100);

            /* Try session again */
            rc = security_get_session_key(packet->header.destination, tmp_key);
            if (rc != 0) {
                sodium_memzero(eph_priv, sizeof(eph_priv));
                return -3; /* No route/session to destination */
            }
            static uint8_t fallback_key[SYMMETRIC_KEY_LENGTH];
            memcpy(fallback_key, tmp_key, SYMMETRIC_KEY_LENGTH);
            session_key = fallback_key;

            sodium_memzero(eph_priv, sizeof(eph_priv));
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
    return mesh_send_packet_internal(packet, session_key);
}

static int mesh_send_packet_internal(packet_t* packet, const uint8_t* key) {
    if (packet_encrypt(packet, key) != 0) {
        return -1;
    }

    uint8_t buf[MAX_PACKET_SIZE];
    int len = packet_serialize(packet, buf, sizeof(buf));
    if (len <= 0) return -2;

    return radio_transmit(buf, (size_t)len, 2000);
}

/* ============================================================================
 * Routing and neighbor management
 * ============================================================================ */

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

int mesh_update_routing(uint16_t source, uint16_t from_node, int16_t rssi, uint8_t band) {
    if (source == 0 || source == mesh_state.our_node_id) return -1;

    if (from_node == 0) {
        mesh_add_neighbor(source, band, rssi);
        mesh_add_route(source, source, 1, rssi, band);
    } else {
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

int mesh_get_neighbor(uint16_t node_id, neighbor_t* neighbor) {
    if (!neighbor) return -1;
    int idx = mesh_find_neighbor_index(node_id);
    if (idx < 0) return 1; /* Not found */
    *neighbor = mesh_state.neighbors[idx];
    return 0;
}

int mesh_update_neighbor(uint16_t node_id, uint8_t band, int16_t rssi) {
    return mesh_add_neighbor(node_id, band, rssi);
}

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

/* ============================================================================
 * Internal helpers
 * ============================================================================ */

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

static int mesh_find_route_index(uint16_t dest_id) {
    for (int i = 0; i < MAX_ROUTE_ENTRIES; i++) {
        if (mesh_state.routes[i].dest_id == dest_id) {
            return i;
        }
    }
    return -1;
}

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

    if (idx >= 0) {
        mesh_state.neighbors[idx].node_id   = node_id;
        mesh_state.neighbors[idx].bands     = 0x07; /* Assume all bands */
        mesh_state.neighbors[idx].rssi[band]= (int8_t)rssi;
        mesh_state.neighbors[idx].last_seen = platform_get_time_ms();
        mesh_state.neighbors[idx].is_active = 1;
    }

    return 0;
}

static int mesh_find_neighbor_index(uint16_t node_id) {
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (mesh_state.neighbors[i].node_id == node_id) {
            return i;
        }
    }
    return -1;
}

/* ============================================================================
 * Radio callback glue
 * ============================================================================ */

static void mesh_rx_handler(uint8_t* data, size_t len, int16_t rssi, int8_t snr) {
    packet_t pkt;
    if (packet_deserialize(data, len, &pkt) != 0) return;

    /* Try decrypting with network key first for beacons/handshakes */
    if (pkt.header.type == PACKET_TYPE_BEACON || pkt.header.type == PACKET_TYPE_HANDSHAKE) {
        if (packet_decrypt(&pkt, mesh_state.network_key) == 0) {
            int handled = packet_handle(&pkt, 0);
            if (handled >= 0) {
                mesh_process_packet(&pkt, rssi, snr);
            }
            return;
        }
    }

    /* Otherwise try per-source session keys */
    uint8_t key[SYMMETRIC_KEY_LENGTH];
    int rc = security_get_session_key(pkt.header.source, key);
    if (rc == 0 && packet_decrypt(&pkt, key) == 0) {
        int handled = packet_handle(&pkt, 0);
        if (handled >= 0) {
            mesh_process_packet(&pkt, rssi, snr);
        }
    }
}

static void mesh_tx_handler(void) {
    /* Post-transmission handling; no-op for now */
}

static void mesh_error_handler(uint16_t error) {
    platform_log(LOG_LEVEL_WARNING, "Radio error: 0x%04X", error);
}

/* ============================================================================
 * Group management functions: used by application/CLI to manage groups.
 * ============================================================================ */

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
        uint8_t eph_pub[PUBLIC_KEY_LENGTH], eph_priv[PRIVATE_KEY_LENGTH];
        crypto_box_keypair(eph_pub, eph_priv);

        handshake_message_t hello;
        memset(&hello, 0, sizeof(hello));
        hello.type          = HANDSHAKE_TYPE_HELLO;
        hello.initiator_id  = leader_id;
        hello.responder_id  = member_id;
        memcpy(hello.public_key, eph_pub, PUBLIC_KEY_LENGTH);

        packet_t hpkt;
        if (packet_create(&hpkt, BROADCAST_ADDR, PACKET_TYPE_HANDSHAKE,
                          (uint8_t*)&hello, sizeof(hello)) == 0) {
            mesh_send_packet_internal(&hpkt, mesh_state.network_key);
        }

        platform_delay_ms(100); /* Wait for response in sim; real impl would queue/retry */

        rc = security_get_session_key(member_id, sess_key);
        if (rc != 0) {
            sodium_memzero(eph_priv, sizeof(eph_priv));
            return -3; /* No session with member after handshake attempt */
        }

        sodium_memzero(eph_priv, sizeof(eph_priv));
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
