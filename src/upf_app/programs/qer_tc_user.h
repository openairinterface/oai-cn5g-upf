#ifndef __QER_TC_USER_H__
#define __QER_TC_USER_H__

#include <ProgramLifeCycle.hpp>
#include <atomic>
#include <linux/bpf.h>  // manage maps (e.g. bpf_update*)
#include <memory>
#include <mutex>
#include <signal.h>  // signals
#include <qer_tc_kernel_skel.h>
#include <wrappers/BPFMap.hpp>
#include <BPFProgram.h>
#include "interfaces.h"

#include <netlink/netlink.h>
#include <netlink/route/qdisc.h>
#include <helpers/QdiscHelpers.hpp>
#include <pdu_session.h>
#include <qos_flow.h>
#include "gtp_u_tunnel_key.h"
#include <pfcp_session.hpp>
class BPFMaps;
class BPFMap;
class SessionManager;
class RulesUtilities;

using QERProgramLifeCycle = ProgramLifeCycle<qer_tc_kernel_c>;

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
  explicit QERProgram();

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
   * @param const std::string&
   * @param const std::string&
   * @param const char*
   * @param std::vector<struct s_fiveQosFlow*>
   * @param uint64_t
   * @param struct gtpUTunnel*
   */
  void setup(uint64_t seid, std::vector<std::shared_ptr<pfcp::pfcp_qer>> pQer);
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
   * @param uint32_t
   * @param uint32_t
   */
  void updateProgramMap(uint32_t key, uint32_t fd);

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Remove program in map.
   *
   * @param uint32_t
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

  std::shared_ptr<BPFMap> getEgressIfindexMap() const;

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Get the n3 GTP-U Tunnel Map object.
   *
   * @return std::shared_ptr<BPFMap>  The seid value of the PDU session
   * associated with the n3 GTP-U Tunnel.
   */
  std::shared_ptr<BPFMap> geGtpUTunnelMap() const;

  std::shared_ptr<BPFMap> getSdfFilterMap() const;

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Get the Filter Map object.
   *
   * @return std::shared_ptr<BPFMap> The filter.
   */
  std::shared_ptr<BPFMap> getFilterMap() const;

  /*---------------------------------------------------------------------------------------------------------------*/
  std::shared_ptr<BPFMap> get5GQoSFlowParamsMap() const;

  /*---------------------------------------------------------------------------------------------------------------*/

  std::shared_ptr<BPFMap> getQoSFlowMap() const;

  std::shared_ptr<BPFMap> getEgressInterfaceMap() const;
  /*---------------------------------------------------------------------------------------------------------------*/

  /**
   * @brief Create a configure hierarchy object
   *
   * @param sock
   * @param interface
   * @param child_ids
   */
  void createConfigureHierarchy(
      struct nl_sock* sock, const char* interface,
      std::vector<std::vector<uint32_t>> childIds);
  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Create a parent parent class object
   *
   * @param sock
   * @param interface
   * @param parent_id
   * @return * struct rtnl_qdisc*
   */
  struct rtnl_qdisc* createParentClass(
      struct nl_sock* sock, const char* interface, uint32_t parentId);

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Create a child class object
   *
   * @param sock
   * @param parent
   * @param child_id
   * @return struct rtnl_qdisc*
   */
  struct rtnl_qdisc* createChildClass(
      struct nl_sock* sock, struct rtnl_qdisc* parent, uint32_t childId);

  /*---------------------------------------------------------------------------------------------------------------*/
  //   /**
  //    * @brief Setter
  //    * Save the QFI vector
  //    *
  //    * @param pQer
  //    */
  //   void setQosFlowsQfis(std::shared_ptr<pfcp::pfcp_qer> pQer);

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Set the pdu session ids object
   *
   * @param seid
   * @param gtp_tunnel
   */
  void setPduSessionIds(uint64_t seid, struct gtpUTunnel* gtpTunnel);
  // void set_pdu_session_ids(uint64_t seid);

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Set the PDU session Qdisc Class Attributes
   * @param const char *
   * @param const char *
   */
  void setPduSessionClassAttributes(
      const char* qdiscScheduler, std::string interface);

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Set the qos flows classes attributes object
   *
   */
  void setQosFlowsClassesAttributes();

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Set the pdu session class position object
   *
   */
  void setPduSessionClassPosition(uint64_t seid);

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Set the qos flows classes positions object
   *
   */
  void setQosFlowsClassesPositions();

  struct qer_tc_kernel_c* get_bpf_skel_object();
  int teardown_hook(int ifindex);
  int tc_detach_egress(int ifindex);
  int tc_attach_egress(
      int ifindex, struct qer_tc_kernel_c* obj, const char* section_name);
  int tc_attach_ingress(
      int ifindex, struct qer_tc_kernel_c* obj, const char* section_name);
  int add_clsact_qdisc(int ifindex, enum bpf_tc_attach_point attach_point);
  bool no_htb_root_qdisc(std::string interface);
  /*---------------------------------------------------------------------------------------------------------------*/
 private:
  /**
   * @brief Initialize BPF wrappers maps.
   *
   */
  void initializeMaps();

  void insertValuesIntoMaps();
  void storeQosFlow(std::shared_ptr<pfcp::pfcp_qer> pQer);
  /*---------------------------------------------------------------------------------------------------------------*/
  // The reference of the bpf maps.
  std::shared_ptr<BPFMaps> mpMaps;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The skeleton of the UPF program generated by bpftool.
  // ProgramLifeCycle is the owner of the pointer.
  qer_tc_kernel_c* spSkeleton;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The GTP-U Tunnel map.
  std::shared_ptr<BPFMap> mpGtpUTunnelMap;

  std::shared_ptr<BPFMap> mpEgressIfindexMap;
  /*---------------------------------------------------------------------------------------------------------------*/

  // The BPF lifecycle program.
  std::shared_ptr<QERProgramLifeCycle> mpLifeCycle;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The Filter map.
  std::shared_ptr<BPFMap> mpFilterMap;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The SDF Filter map.
  std::shared_ptr<BPFMap> mpSdfFilterMap;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The 5G QoS Flow Parameters map.
  std::shared_ptr<BPFMap> mp5GQoSFlowParamsMap;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The 5G QoS Flow.
  std::shared_ptr<BPFMap> mpQoSFlowMap;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The GTP interface.
  std::string mGTPInterface;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The UDP interface.
  std::string mUDPInterface;

  /*---------------------------------------------------------------------------------------------------------------*/

  // std::vector<struct rtnl_qdisc *> parent_qdiscs;
  // std::vector<std::vector<struct rtnl_qdisc *>> child_qdiscs;

  struct rtnl_class* classPduSession = nullptr;
  std::vector<struct rtnl_class*> classesQfiFlows;

  struct classParams* pduSessionClassAtt   = nullptr;
  struct classPosition* pduSessionClassPos = nullptr;

  std::vector<struct classParams*> qosFlowsClassesAtt;
  std::vector<struct classPosition*> qosFlowsClassesPos;
  std::vector<struct s_fiveQosFlow> qosFlowsQfis;
  std::vector<std::shared_ptr<pfcp::pfcp_qer>> savedQers;

  struct pduSessionIds* pduSession = nullptr;
};

#endif  // __QER_TC_USER_H__
