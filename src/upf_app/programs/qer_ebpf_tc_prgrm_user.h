#ifndef __QER_EBPF_TC_PRGRM_USER_H__
#define __QER_EBPF_TC_PRGRM_USER_H__

#include <ProgramLifeCycle.hpp>
#include <atomic>
#include <linux/bpf.h>  // manage maps (e.g. bpf_update*)
#include <memory>
#include <mutex>
#include <signal.h>  // signals
#include <qer_ebpf_tc_prgrm_kernel_skel.h>
#include <wrappers/BPFMap.hpp>
#include <BPFProgram.h>
#include "interfaces.h"

#include "interfaces.h"

#include <netlink/netlink.h>
#include <netlink/route/qdisc.h>
#include <helpers/QdiscHelpers.hpp>
#include <pdu_session.h>
#include <qos_flow.h>


class BPFMaps;
class BPFMap;
class SessionManager;
class RulesUtilities;

using QERProgramLifeCycle = ProgramLifeCycle<qer_ebpf_tc_prgrm_kernel_c>;


/**
 * @brief Singleton class to abstract the UPF bpf tc program.
 */
class QERProgram : public BPFProgram {
 public:
/*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Construct a new QERProgram object.
   *
   */
  explicit QERProgram(const std::string& gtpInterface, const std::string& udpInterface);


/*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Destroy the QERProgram object
   */
  virtual ~QERProgram();


/*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Setup the tc BPF program when QoS Feature is disabled
   *
   */
  void setup();


/*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Setup tc BPF program when QoS Feature is enabled
   * 
   * @param gtpInterface 
   * @param udpInterface 
   * @param qdisc_scheduler 
   * @param qfis 
   */
  void setup(const std::string& gtpInterface, const std::string& udpInterface, const char* qdisc_scheduler, std::vector<uint32_t> qfis);
  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Get the BPFMaps object.
   *
   * @return std::shared_ptr<BPFMaps> The reference of the BPFMaps.
   */
  std::shared_ptr<BPFMaps> getMaps();

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Tear downs the BPF program.
   *
   */
  void tearDown();
  /*---------------------------------------------------------------------------------------------------------------*/

  /**
   * @brief Update program int map.
   *
   * @param key The key which will be inserted the program file descriptor.
   * @param fd The file descriptor.
   */
  void updateProgramMap(uint32_t key, uint32_t fd);

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Remove program in map.
   *
   * @param key The key which will be remove in the program map.
   */
  void removeProgramMap(uint32_t key);
  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Get the TEID to session Map object.
   *
   * @return std::shared_ptr<BPFMap> The TEID to fd map.
   */
  std::shared_ptr<BPFMap> getQERMap() const;

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Get the Egress Interface Map object.
   *
   * @return std::shared_ptr<BPFMap> The egress interface map.
   */
  std::shared_ptr<BPFMap> getEgressInterfaceMap() const;

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Get the n3 GTP-U Tunnel Map object.
   *
   * @return std::shared_ptr<BPFMap>  The seid value of the PDU session associated
   * with the n3 GTP-U Tunnel.
   */
  std::shared_ptr<BPFMap> geGtpUTunnelMap() const;

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Get the Filter Map object.
   *
   * @return std::shared_ptr<BPFMap> The filter.
   */
  std::shared_ptr<BPFMap> getFilterMap() const;

  /*---------------------------------------------------------------------------------------------------------------*/
  
  


                     
    
  /*---------------------------------------------------------------------------------------------------------------*/
 
  /**
   * @brief Create a configure hierarchy object
   * 
   * @param sock 
   * @param interface 
   * @param child_ids 
   */
  void create_configure_hierarchy(struct nl_sock *sock, const char *interface, std::vector<std::vector<uint32_t>> child_ids);
  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Create a parent parent class object
   * 
   * @param sock 
   * @param interface 
   * @param parent_id 
   * @return * struct rtnl_qdisc* 
   */
  struct rtnl_qdisc *create_parent_class(struct nl_sock *sock, const char *interface, uint32_t parent_id);

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Create a child class object
   * 
   * @param sock 
   * @param parent 
   * @param child_id 
   * @return struct rtnl_qdisc* 
   */
  struct rtnl_qdisc *create_child_class(struct nl_sock *sock, struct rtnl_qdisc *parent, uint32_t child_id);
  

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Setter
   * Save the QFI vector
   * 
   * @param qfis 
   */
  void set_qos_flows_qfis(std::vector<struct qos_flow*> qfis);


  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Set the pdu session ids object
   * 
   * @param seid 
   */
  void set_pdu_session_ids(uint64_t seid);

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Set the PDU session Qdisc Class Attributes
   * @param const char *
   */
  void set_pdu_session_class_attributes(const char *qdisc_scheduler); 


  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Set the qos flows classes attributes object
   * 
   */
  void set_qos_flows_classes_attributes();

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Set the pdu session class position object
   * 
   */
  void set_pdu_session_class_position();

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Set the qos flows classes positions object
   * 
   */
  void set_qos_flows_classes_positions();


/*---------------------------------------------------------------------------------------------------------------*/
 private:
  /**
   * @brief Initialize BPF wrappers maps.
   *
   */
  void initializeMaps();

  /*---------------------------------------------------------------------------------------------------------------*/
  // The reference of the bpf maps.
  std::shared_ptr<BPFMaps> mpMaps;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The skeleton of the UPF program generated by bpftool.
  // ProgramLifeCycle is the owner of the pointer.
  qer_ebpf_tc_prgrm_kernel_c* spSkeleton;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The GTP-U Tunnel map.
  std::shared_ptr<BPFMap> mpGtpUTunnelMap;

  /*---------------------------------------------------------------------------------------------------------------*/
 
  // The BPF lifecycle program.
  std::shared_ptr<QERProgramLifeCycle> mpLifeCycle;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The Filter map.
  std::shared_ptr<BPFMap> mpFilterMap;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The GTP interface.
  std::string mGTPInterface;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The UDP interface.
  std::string mUDPInterface;
  
  /*---------------------------------------------------------------------------------------------------------------*/
  
  // std::vector<struct rtnl_qdisc *> parent_qdiscs;
  // std::vector<std::vector<struct rtnl_qdisc *>> child_qdiscs;
  
  struct rtnl_class* class_pdu_session = nullptr;
  std::vector<struct rtnl_class*> classes_qfi_flows;

  struct class_params *pdu_session_class_att = nullptr;
  struct class_position *pdu_session_class_pos = nullptr;

  std::vector<struct class_params*> qos_flows_classes_att;
  std::vector<struct class_position*> qos_flows_classes_pos;
  std::vector<struct qos_flow*> qos_flows_qfis;

  struct pdu_session_ids* pdu_session = nullptr;
  
};

#endif  // __QER_EBPF_TC_PRGRM_USER_H__

