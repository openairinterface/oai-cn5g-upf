import time
import uuid
from datetime import datetime
from threading import Thread, Event
import scapy.sendrecv
from scapy.contrib.gtp import GTP_U_Header, GTPPDUSessionContainer
from scapy.layers.inet import IP, UDP

from scapy.contrib.pfcp import IE_ApplyAction, \
    IE_CreateFAR,                     \
    IE_CreatePDR,                     \
    IE_DestinationInterface,          \
    IE_FAR_Id,                        \
    IE_ForwardingParameters,          \
    IE_FSEID,                         \
    IE_NetworkInstance,               \
    IE_NodeId,                        \
    IE_PDI,                           \
    IE_PDR_Id,                        \
    IE_Precedence,                    \
    IE_RecoveryTimeStamp,             \
    IE_SourceInterface,               \
    IE_UE_IP_Address,                 \
    IE_FTEID,                         \
    IE_OuterHeaderCreation,           \
    IE_OuterHeaderRemoval,            \
    PFCP,                             \
    PFCPAssociationSetupRequest,      \
    PFCPSessionEstablishmentRequest,  \
    PFCPSessionModificationRequest,   \
    IE_CPFunctionFeatures,            \
    PFCPSessionEstablishmentResponse, \
    IE_CreatedPDR,                    \
    IE_QFI,                           \
    PFCPHeartbeatResponse,            \
    IE_SequenceNumber,                \
    PFCPHeartbeatRequest

#--------------------------------------------------------------------------------------------------------
def generate_unique_ip(base_ip, offset):
    """Generate a unique IP that stays within the 12.1.x.x subnet, starting from 12.1.1.3"""
    octets       = base_ip.split('.')
    third_octet  = int(octets[2])   
    fourth_octet = int(octets[3])   
    
    new_fourth_octet = fourth_octet + offset
    new_third_octet  = third_octet + (new_fourth_octet // 256) 
    new_fourth_octet = new_fourth_octet % 256  

    if new_third_octet > 255:
        raise ValueError("Exceeded IP address range in the 12.1.x.x subnet")

    return f"12.1.{new_third_octet}.{new_fourth_octet}"

#--------------------------------------------------------------------------------------------------------
def generate_unique_fteid(base_fteid, offset):
    """Generate a unique FTEID by incrementing the base FTEID."""
    return base_fteid + offset

#--------------------------------------------------------------------------------------------------------
def generate_unique_seid(base_seid, offset):
    """Generate a unique SEID by incrementing the base SEID."""
    return base_seid + offset

#--------------------------------------------------------------------------------------------------------
def ie_fteid_set(fteid, ipv4):
    return IE_FTEID(V4=1, TEID=fteid, ipv4=ipv4)

#--------------------------------------------------------------------------------------------------------
def ie_fteid():
    return IE_FTEID(CH=1, V4=1)

#--------------------------------------------------------------------------------------------------------
def ie_fteid_ch(chid):
    return IE_FTEID(CH=1, CHID=1, choose_id=chid, V4=1)

#--------------------------------------------------------------------------------------------------------
def outer_header_creation(fteid, ipv4):
    return IE_OuterHeaderCreation(
        GTPUUDPIPV4=1, TEID=fteid, ipv4=ipv4)

#--------------------------------------------------------------------------------------------------------
def create_pdr_ul(pdr_id, far_id, nwi, sdf_filter, source_iface, ip, sd):
    return IE_CreatePDR(IE_list=[
        IE_PDR_Id(id=pdr_id),
        IE_Precedence(precedence=0),
        IE_PDI(IE_list=[
            IE_SourceInterface(interface=source_iface),
            ie_fteid_ch(42),
            IE_NetworkInstance(instance=nwi),
            IE_UE_IP_Address(ipv4=ip, V4=1, SD=sd),
        ]),
        IE_OuterHeaderRemoval(header="GTP-U/UDP/IPv4"),
        IE_FAR_Id(id=far_id),
    ])

#--------------------------------------------------------------------------------------------------------
def create_pdr_dl(pdr_id, far_id, nwi, sdf_filter, source_iface, ip, sd):
    return IE_CreatePDR(IE_list=[
        IE_PDR_Id(id=pdr_id),
        IE_Precedence(precedence=0),
        IE_PDI(IE_list=[
            IE_SourceInterface(interface=source_iface),
            IE_NetworkInstance(instance=nwi),
            IE_UE_IP_Address(ipv4=ip, V4=1, SD=sd)
        ]),
        IE_FAR_Id(id=far_id)
    ])

#--------------------------------------------------------------------------------------------------------
def create_far_ul(far_id, nwi):
    return IE_CreateFAR(IE_list=[
        IE_FAR_Id(id=far_id),
        IE_ApplyAction(FORW=1),
        IE_ForwardingParameters(IE_list=[
            IE_DestinationInterface(interface="Core"),
            IE_NetworkInstance(instance=nwi),
        ])
    ])

#--------------------------------------------------------------------------------------------------------
def create_far_dl(far_id, nwi, fteid, ipv4):
    return IE_CreateFAR(IE_list=[
        IE_FAR_Id(id=far_id),
        IE_ApplyAction(FORW=1),
        IE_ForwardingParameters(IE_list=[
            IE_DestinationInterface(interface="Access"),
            IE_NetworkInstance(instance=nwi),
            outer_header_creation(fteid, ipv4)
        ])
    ])

#--------------------------------------------------------------------------------------------------------
def session_establishment_ul(seid_, ue_ip, smf_ip, pdr_id_ul, far_id_ul):
    """Create a PFCP Session Establishment request for uplink traffic."""
    return PFCPSessionEstablishmentRequest(IE_list=[
        IE_NodeId(id_type="FQDN", id=smf_ip),
        IE_FSEID(seid=seid_, ipv4=smf_ip, v4=1),
        create_pdr_ul(pdr_id_ul, far_id_ul, "access.oai.org", "permit out ip from any to assigned", "Access", ue_ip, 0),  
        create_far_ul(far_id_ul, "core.oai.org")
    ])

#--------------------------------------------------------------------------------------------------------
def session_modification_dl(seid_, ue_ip, fteid_dl, smf_ip, gnb_ip, pdr_id_dl, far_id_dl):
    return PFCPSessionModificationRequest(IE_list=[
        IE_FSEID(seid=seid_, ipv4=smf_ip, v4=1),
        create_pdr_dl(pdr_id_dl, far_id_dl, "core.oai.org", "permit out ip from any to assigned", "Core", ue_ip, 1),
        create_far_dl(far_id_dl, "access.oai.org", fteid_dl, gnb_ip),
    ])

#--------------------------------------------------------------------------------------------------------
def association(smf_ip):
    ts = int((datetime.now() - datetime(1900, 1, 1)).total_seconds())
    return (PFCPAssociationSetupRequest(IE_list=[
        IE_NodeId(id_type="FQDN", id=smf_ip),
        IE_RecoveryTimeStamp(timestamp=ts),
        IE_CPFunctionFeatures(OVRL=1, LOAD=1)
    ]))

#--------------------------------------------------------------------------------------------------------
def send_receive_pfcp(msg, seid_=None, recv=True, seq=None, seq_counter=None, smf_ip=None, upf_ip_n4=None):
    if seq_counter is None:
        raise ValueError("seq_counter must be provided if seq is not specified.")

    seq = seq if seq else seq_counter

    pfcp = PFCP(version=1, seq=seq,
                S=0 if seid_ is None else 1,
                seid=0 if seid_ is None else seid_)

    pkt = IP(src=smf_ip, dst=upf_ip_n4, proto=17) / UDP(sport=8805, dport=8805) / pfcp / msg
    if recv:
        res = scapy.sendrecv.sr1(pkt)
        print(res)
        return res
    else:
        scapy.sendrecv.send(pkt)


#--------------------------------------------------------------------------------------------------------

def create_pdu_sessions(num_sessions, first_seid, first_ue_ip, first_fteid_dl, smf_ip, upf_ip_n4, gnb_ip, first_pdr_ul, first_far_ul, first_pdr_dl, first_far_dl, first_seq_number):
    print("Send PFCP Association Request")
    send_receive_pfcp(association(smf_ip), seq_counter=first_seq_number, smf_ip=smf_ip, upf_ip_n4=upf_ip_n4)


    for i in range(1, num_sessions + 1):
        unique_session_id = generate_unique_seid(first_seid, i - 1)
        unique_ue_ip      = generate_unique_ip(first_ue_ip, i - 1)
        unique_fteid_dl   = generate_unique_fteid(first_fteid_dl, i - 1)

        pdr_id_ul = first_pdr_ul + i
        far_id_ul = first_pdr_ul + i
        pdr_id_dl = first_pdr_dl + i
        far_id_dl = first_far_dl + i

        seq_number = first_seq_number +i

        print(f"Creating PDU session {i}/{num_sessions} with SEID {unique_session_id} and UE IP {unique_ue_ip}")
        
        res = send_receive_pfcp(session_establishment_ul(unique_session_id, unique_ue_ip, smf_ip, pdr_id_ul, far_id_ul), seid_=0, seq_counter=seq_number, smf_ip=smf_ip, upf_ip_n4=upf_ip_n4)


        session_resp = res[PFCPSessionEstablishmentResponse]
        created_fteid = session_resp[IE_CreatedPDR][IE_FTEID].TEID
        print(f"Session {i}: Created FTEID: {hex(created_fteid)} with UE IP {unique_ue_ip}")
        
        send_receive_pfcp(session_modification_dl(unique_session_id, unique_ue_ip, unique_fteid_dl, smf_ip, gnb_ip, pdr_id_dl, far_id_dl), seid_=unique_session_id, seq_counter=seq_number, smf_ip=smf_ip, upf_ip_n4=upf_ip_n4)

        time.sleep(0.01)  # Small delay to avoid overwhelming the system

#--------------------------------------------------------------------------------------------------------
def main():
    num_sessions   = 5000

    smf_ip         = "192.168.199.110"
    upf_ip_n4      = "192.168.199.227"
    gnb_ip         = "192.168.10.100"
    first_ue_ip    = "12.1.1.2" #"192.168.10.100" 

    first_fteid_ul = 0x00000001
    first_fteid_dl = int(hex(num_sessions + 1), 16)
    first_seid     = 0x00000001
    
    first_pdr_ul = 0
    first_far_ul = 0
    first_pdr_dl = num_sessions
    first_far_dl = num_sessions

    first_seq_number     = 16770408
    
    
    create_pdu_sessions(num_sessions, first_seid, first_ue_ip, first_fteid_dl, smf_ip, upf_ip_n4, gnb_ip, first_pdr_ul, first_far_ul, first_pdr_dl, first_far_dl, first_seq_number)

#--------------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    main()
