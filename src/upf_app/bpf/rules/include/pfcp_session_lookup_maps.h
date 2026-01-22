#ifndef __PFCP_SESSION_LOOKUP_MAPS_H__
#define __PFCP_SESSION_LOOKUP_MAPS_H__

#include <bpf_helpers.h>
#include <ie/group_ie/create_pdr.h>
#include <pfcp/pfcp_pdr.h>
#include <pfcp/pfcp_far.h>
#include <pfcp/pfcp_session.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <ie/teid.h>
#include <mac_pdu_session_key.h>
#include <rules_matching_pdr.h>
#include "interfaces.h"
#include "session_id.h"

#define MAX_PDRS_PER_SESSION 32
#define MAX_ETH_PDU_SESSIONS 500

const volatile int max_upf_interfaces SEC(".rodata");
const volatile int max_upf_redirect_interfaces SEC(".rodata");
const volatile int max_pdu_session SEC(".rodata");
const volatile int max_pdrs_per_pdu_session SEC(".rodata");
const volatile int max_sdf_filters_per_pdu_session SEC(".rodata");
const volatile int max_arp_entries SEC(".rodata");
const volatile int max_qos_enabling SEC(".rodata");

/**
 * m_upf_interfaces: Stores network interface configuration for UPF reference
 * points
 *
 * Purpose: Maps 5G reference points (N3, N4, N6, N9) to their physical network
 * interfaces. Used to determine which interface to use for sending/receiving
 * packets based on the traffic direction and purpose.
 *
 * Type: BPF_MAP_TYPE_HASH - Hash table for fast interface lookup
 *
 * Max Entries: max_upf_interfaces (default: 3)
 *   Rationale: Typical UPF deployment uses 3 main interfaces:
 *              - N3: Interface toward RAN (Radio Access Network) for user plane
 * traffic
 *              - N4: Interface toward SMF for PFCP control messages
 *              - N6: Interface toward Data Network (internet/enterprise
 * networks)
 *              - N9: (Optional) Interface for inter-UPF communication
 *
 * Key: e_reference_point (enum)
 *   - Identifies which 5G reference point (N3, N4, N6, N9)
 *
 * Value: struct s_interface
 *   - Contains interface details: name, index, IP address, MAC address
 *   - Used for packet forwarding decisions and header construction
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* max_upf_interfaces */
  __type(key, e_reference_point);
  __type(value, struct s_interface);
} m_upf_interfaces SEC(".maps");

/**
 * m_sdf_filter: Stores Service Data Flow (SDF) filters for traffic
 * classification
 *
 * Purpose: Contains packet filtering rules to classify and differentiate
 * traffic flows within a PDU session based on IP 5-tuple (src/dst IP, src/dst
 * port, protocol). SDF filters enable application-specific QoS treatment.
 *
 * Type: BPF_MAP_TYPE_HASH - Hash table for efficient filter lookup
 *
 * Max Entries: max_sdf_filters_per_pdu_session (default: 8)
 *   Rationale: Limits the number of distinct traffic flows that can be
 * classified per session.
 *
 * Key: struct session_qfi
 *   - Composite key: <QFI (QoS Flow Identifier), SEID>
 *   - QFI identifies the QoS flow within a session
 *   - SEID identifies the PDU session
 *
 * Value: struct sdf_filtr
 *   - Contains matching criteria: IP addresses, ports, protocol, direction
 *   - Defines which packets belong to this specific service data flow
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);           /* max_sdf_filters_per_pdu_session */
  __type(key, struct session_qfi);  // <qfi, seid>
  __type(value, struct sdf_filtr);
} m_sdf_filter SEC(".maps");

/**
 * m_session_mapping: Maps UE IP addresses to session identifiers and TEIDs
 *
 * Purpose: Primary lookup table for incoming packets to find the associated
 * session. Enables fast resolution from UE IP address to session context (SEID
 * and TEIDs). Critical for both uplink (from UE) and downlink (to UE) packet
 * processing.
 *
 * Type: BPF_MAP_TYPE_HASH - Hash table for O(1) IP-to-session lookup
 *
 * Max Entries: max_pdu_session (default: 10,000)
 *   Rationale: One entry per PDU session. Each UE typically has 1-2 sessions
 *              (e.g., internet + IMS), so this supports thousands of concurrent
 * UEs.
 *
 * Key: u32 ue_ip_address
 *   - IPv4 address assigned to the UE for this PDU session
 *   - Extracted from packet headers for fast session lookup
 *
 * Value: struct session_id
 *   - teid_ul: Tunnel Endpoint Identifier for uplink (UE->gNB->UPF)
 *   - teid_dl: Tunnel Endpoint Identifier for downlink (UPF->gNB->UE)
 *   - seid: Session Endpoint Identifier for PFCP session management
 *   - Used to locate PDRs and FARs for packet forwarding decisions
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);            /* max_pdu_session */
  __type(key, u32);                  // ue_ip_address
  __type(value, struct session_id);  // < teid_ul, teid_dl, seid >
} m_session_mapping SEC(".maps");

/**
 * m_session_pdrs: Stores all Packet Detection Rules (PDRs) for each PDU session
 *
 * Purpose: This is the primary map for fast lookup of PDRs during packet
 * processing. For each session (identified by SEID), it stores an array of all
 * PDRs that apply to that session, sorted by precedence (lower value = higher
 * priority).
 *
 * Type: BPF_MAP_TYPE_HASH - Hash table for O(1) lookup by SEID
 *
 * Max Entries: max_pdu_session
 *   Rationale: One entry per PDU session. Each UE can have one or more
 * sessions, and the UPF must support up to max_pdu_session concurrent sessions.
 *
 * Key: u64 seid (Session Endpoint Identifier)
 *   - Unique identifier for each PDU session
 *   - Assigned by the control plane (SMF) during session establishment
 *
 * Value: pfcp_pdr_t_[MAX_PDRS_PER_SESSION] (array of up to 32 PDRs)
 *   - Each session can have multiple PDRs for different traffic flows
 *   - PDRs define: packet matching criteria, QoS rules, forwarding actions
 *   - Array is sorted by precedence to enable fast sequential matching
 *   - MAX_PDRS_PER_SESSION (32) is the maximum PDRs per session supported
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* max_pdu_session */
  __type(key, u64);       // seid
  __type(value, pfcp_pdr_t_[MAX_PDRS_PER_SESSION]);
} m_session_pdrs SEC(".maps");

/**
 * m_rules_match_pdr: Associates PDRs with their corresponding action rules
 * (FAR, QER, etc.)
 *
 * Purpose: Links each Packet Detection Rule (PDR) to its enforcement rules.
 * When a packet matches a PDR, this map provides the actions to take:
 *          - FAR (Forwarding Action Rule): forward, drop, buffer, or duplicate
 *          - QER (QoS Enforcement Rule): rate limiting, packet marking
 *          - URR (Usage Reporting Rule): accounting and statistics (future)
 *
 * Type: BPF_MAP_TYPE_HASH - Hash table for fast rule lookup
 *
 * Max Entries: max_pdrs_per_pdu_session * max_pdu_session (default: 8 * 10,000
 * = 80,000) Rationale: One entry per PDR across all sessions. Each session has
 * up to max_pdrs_per_pdu_session PDRs, so total capacity is: (8 PDRs/session) ×
 * (10,000 sessions) = 80,000 entries This ensures every PDR can have associated
 * enforcement rules.
 *
 * Key: struct pdrs_per_session
 *   - Composite key: <pdr_id, seid>
 *   - Uniquely identifies a specific PDR within a specific session
 *
 * Value: struct rules_match_pdr
 *   - Contains references/IDs to FAR, QER, and potentially MAR, BAR, URR
 *   - Enables packet processing pipeline: detect (PDR) → enforce (FAR/QER)
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* max_pdrs_per_pdu_session * max_pdu_session */
  __type(key, struct pdrs_per_session);   // < pdr_id, seid >
  __type(value, struct rules_match_pdr);  // < FAR, QER, /* MAR, BAR, URR */ >
} m_rules_match_pdr SEC(".maps");

/**
 * m_qos_enabling: Tracks whether QoS enforcement is enabled for each session
 *
 * Purpose: Flag map to enable/disable QoS processing on a per-session basis.
 *          When enabled, the UPF applies rate limiting, traffic shaping, and
 *          prioritization based on QERs. When disabled, packets bypass QoS
 * logic for better performance.
 *
 * Type: BPF_MAP_TYPE_HASH - Hash table for per-session QoS control
 *
 * Max Entries: max_pdu_session (default: 10,000)
 *   Rationale: One flag per PDU session. Allows fine-grained control over which
 *              sessions require QoS enforcement (e.g., premium subscribers) vs
 *              best-effort sessions that don't need the overhead.
 *
 * Key: u64 seid (Session Endpoint Identifier)
 *   - Identifies the PDU session
 *
 * Value: u32 (boolean flag)
 *   - 0: QoS disabled for this session (fast path)
 *   - 1: QoS enabled for this session (apply QERs)
 *   - Checked during packet processing to conditionally invoke QoS logic
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* max_qos_enabling = max_pdu_session */
  __type(key, u64);       // seid
  __type(value, u32);     // Value type (0 for false, 1 for true)
} m_qos_enabling SEC(".maps");

/**
 * m_framed_route_mapping: Maps framed routing keys to UE IP addresses
 *
 * Purpose: Supports framed routing scenarios (RFC 2865) where routing
 * information is provided by AAA (RADIUS/Diameter) servers. Used in
 * enterprise/fixed wireless scenarios where routing tables need to be
 * dynamically updated based on subscriber authentication attributes.
 *
 * Type: BPF_MAP_TYPE_HASH - Hash table for routing key lookups
 *
 * Max Entries: 1 (placeholder, resized at runtime if needed)
 *   Rationale: Framed routing is an optional feature, rarely used in mobile
 * networks. Most deployments use standard IP routing, so minimal allocation.
 *              Can be increased for fixed wireless or enterprise deployments.
 *
 * Key: u32 hash_framed_routing_key
 *   - Hash of framed routing attributes from AAA server
 *   - Typically derived from Framed-Route or Framed-Routing AVPs
 *
 * Value: u32 ue_ip
 *   - UE IP address associated with this routing context
 *   - Used to install specific routes for this subscriber
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, u32);    // hash_framed_routing_key
  __type(value, u32);  // ue_ip
} m_framed_route_mapping SEC(".maps");

/**
 * framed_routing_flag: Global flag to enable/disable framed routing feature
 *
 * Purpose: Master switch to enable or disable framed routing functionality
 * across the entire UPF instance. When disabled, framed routing lookups are
 * skipped to avoid performance overhead in standard mobile network deployments.
 *
 * Type: BPF_MAP_TYPE_HASH - Simple key-value store
 *
 * Max Entries: 1 (single global flag)
 *   Rationale: Only one entry needed for the entire UPF. This is a global
 *              configuration setting, not per-session or per-UE.
 *
 * Key: u8 (constant: 0)
 *   - Single key used to access the flag value
 *   - Always use key=0 to read/write the flag
 *
 * Value: u8 (boolean)
 *   - 0: Framed routing disabled (default for mobile networks)
 *   - 1: Framed routing enabled (for fixed wireless/enterprise)
 *   - Checked before attempting framed route lookups
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);  // Single entry for the flag
  __type(key, u8);         // Key is a constant, e.g., 0
  __type(value, u8);       // Value indicates if framed routing is enabled
} framed_routing_flag SEC(".maps");

/**
 * m_mac_pdu_session: Maps MAC addresses to PDU session information for Ethernet
 * PDU sessions
 *
 * Purpose: Supports Ethernet PDU session type (as opposed to IP PDU sessions).
 * Used in 5G LAN-type service scenarios where UEs communicate using Ethernet
 * frames (Layer 2) rather than just IP packets. Enables bridging/switching
 * behavior in the UPF for private networks, industrial IoT, and enterprise
 * LANs.
 *
 * Type: BPF_MAP_TYPE_HASH - Hash table for MAC address lookups
 *
 * Max Entries: MAX_ETH_PDU_SESSIONS (500)
 *
 * Key: u8[ETH_ALEN] (6 bytes)
 *   - MAC address of the UE or endpoint device
 *   - ETH_ALEN is typically 6 (standard Ethernet MAC address length)
 *
 * Value: struct mac_pdu_session_value
 *   - Contains session context for this MAC address
 *   - Likely includes SEID, TEID, and forwarding information
 *
 * Pinning: Enabled (__uint(pinning, 1))
 *   - Map is pinned to the BPF filesystem (/sys/fs/bpf/)
 *   - Persists across program reloads for session continuity
 *   - Allows sharing between multiple BPF programs if needed
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(
      max_entries,
      MAX_ETH_PDU_SESSIONS);  // 500 // TODO: check from 3gpp standards
  __type(key, u8[ETH_ALEN]);
  __type(value, struct mac_pdu_session_value);
  __uint(pinning, 1);
} m_mac_pdu_session SEC(".maps");

#endif  // __PFCP_SESSION_LOOKUP_MAPS_H__
