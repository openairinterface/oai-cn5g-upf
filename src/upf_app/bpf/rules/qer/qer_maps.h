#ifndef __QER_MAPS_H__
#define __QER_MAPS_H__

#include <bpf_helpers.h>
#include <linux/bpf.h>
#include <types.h>
#include "gtp_u_tunnel_key.h"
#include "filter_key.h"
#include "qfi_values.h"
#include "standardized_5qi.h"
#include "qos_flow.h"

#define QFI_MAX_ENTRIES 5000
#define FIVE_QI_MAX_ENTRIES 100
#define QOS_FLOWS_MAX_ENTRIES 100
#define MAX_INTERFACES 10
/*---------------------------------------------------------------------------------------------------------------*/
// struct bpf_map_def SEC("maps") m_gtp_u_tunnel = {
//     .type        = BPF_MAP_TYPE_HASH,
//     .key_size    = sizeof(struct gtpUTunnel),  // < teid_ul, teid_dl >
//     .value_size  = sizeof(u32),                // seid
//     .max_entries = QFI_MAX_ENTRIES,
// };

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, QFI_MAX_ENTRIES);  // 10,
  __type(key, struct gtpUTunnel);
  __type(value, s32);
} m_gtp_u_tunnel SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
// struct bpf_map_def SEC("maps") m_sdf_filter = {
//     .type = BPF_MAP_TYPE_HASH,
//     .key_size =
//         sizeof(struct filter_key),  // < src_ip, dst_ip, protocol, dst_port >
//     .value_size  = sizeof(struct session_qfi),      // < seid, QFI >
//     .max_entries = QFI_MAX_ENTRIES,
// };

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, QFI_MAX_ENTRIES);  // 10,
  __type(key, struct filter_key);
  __type(value, struct session_qfi);
} m_sdf_filter SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
// struct bpf_map_def SEC("maps") m_5g_qos_flow_parameters = {
//     .type       = BPF_MAP_TYPE_HASH,
//     .key_size   = sizeof(u32),  // 5qi
//     .value_size = sizeof(struct QosFlowParams),
//     /*
//      * 5qi <
//      *       resource_type,
//      *       default_priority_level,
//      *       packet_delay_budget,
//      *       packet_error_rate,
//      *       default_maximum_data_burst_volume,
//      *       default_averaging_window,
//      *       //example_services
//      *      >
//      */
//     .max_entries = FIVE_QI_MAX_ENTRIES,
// };

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, FIVE_QI_MAX_ENTRIES);
  __type(key, u32);
  __type(value, struct QosFlowParams);
} m_5g_qos_flow_parameters SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
// struct bpf_map_def SEC("maps") m_qos_flow = {
//     .type        = BPF_MAP_TYPE_HASH,
//     .key_size    = sizeof(u32),  // qer_id
//     .value_size  = sizeof(struct s_fiveQosFlow),
//     .max_entries = QOS_FLOWS_MAX_ENTRIES,
// };

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, QOS_FLOWS_MAX_ENTRIES);
  __type(key, u32);
  __type(value, struct s_fiveQosFlow);
} m_qos_flow SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
// struct bpf_map_def SEC("maps") m_egress_ifindex = {
//     .type        = BPF_MAP_TYPE_DEVMAP,
//     .key_size    = sizeof(u32),     // id
//     .value_size  = sizeof(u32),     // tx port
//     .max_entries = MAX_INTERFACES,  // 10,
// };

struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __uint(max_entries, MAX_INTERFACES);
  __type(key, u32);
  __type(value, u32);
} m_egress_ifindex SEC(".maps");

#endif  // __QER_MAPS_H__