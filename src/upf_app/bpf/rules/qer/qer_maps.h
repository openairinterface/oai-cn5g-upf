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
/*---------------------------------------------------------------------------------------------------------------*/
struct bpf_map_def SEC("maps") m_gtp_u_tunnel = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct gtpUTunnel),  // < teid_ul, teid_dl >
    .value_size  = sizeof(u32),                // seid
    .max_entries = QFI_MAX_ENTRIES,
};

/*---------------------------------------------------------------------------------------------------------------*/
struct bpf_map_def SEC("maps") m_filter = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size =
        sizeof(struct filter_key),  // < src_ip, dst_ip, protocol, dst_port >
    .value_size  = sizeof(e_qfi),   // QFI
    .max_entries = QFI_MAX_ENTRIES,
};


/*---------------------------------------------------------------------------------------------------------------*/
struct bpf_map_def SEC("maps") m_5g_qos_flow_parameters = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32), //5qi  
    .value_size  = sizeof(struct QosFlowParams),   
    /*
    * 5qi <  
    *       resource_type, 
    *       default_priority_level, 
    *       packet_delay_budget, 
    *       packet_error_rate, 
    *       default_maximum_data_burst_volume, 
    *       default_averaging_window, 
    *       //example_services
    *      >
    */
    .max_entries = FIVE_QI_MAX_ENTRIES,
};


/*---------------------------------------------------------------------------------------------------------------*/
struct bpf_map_def SEC("maps") m_qos_flow = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32), //qer_id
    .value_size  = sizeof(struct s_fiveQosFlow),   
    .max_entries = QOS_FLOWS_MAX_ENTRIES,
};


#endif  // __QER_MAPS_H__