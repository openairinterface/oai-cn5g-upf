#ifndef __USERPLANECOMPONENT_H__
#define __USERPLANECOMPONENT_H__

#include <bpf/libbpf.h>  // enum libbpf_print_level
#include <memory>
#include <string>
#include <observer/OnStateChangeSessionProgramObserver.h>
#include <helpers/qdisc_parameters.h>

class SessionManager;
class RulesUtilities;
class PFCP_Session_LookupProgram;
class PFCP_Session_PDR_LookupProgram;


// struct qdisc_params {
//   const char *scheduler;
//   uint32_t rate;
//   uint32_t ceil;
//   uint32_t rate_buffer;
//   uint32_t ceil_buffer;
//   uint32_t quantum;
//   int level;
// };

/**
 * @brief User Plane component class to abstract the BPF Service Function Chain
 * for mobile core network.
 *
 */
class UserPlaneComponent : public OnStateChangeSessionProgramObserver {
    public:

    /**
     * @brief Destroy the User Plane Component object
     * 
     */
    virtual ~UserPlaneComponent();

    /*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Get the Instance object.
     *
     * @return The singleton instance.
     */
    static UserPlaneComponent& getInstance();

    /*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Setup User Plane Component.
     * Used to setup all the program.
     *
     * @param pRulesUtilities
     * @param gtpInterface
     * @param udpInterface
     */
    void setup(
        std::shared_ptr<RulesUtilities> pRulesUtilities,
        const std::string& gtpInterface, 
        const std::string& udpInterface);
    
    /*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Setup User Plane Component.
     * Used to setup all the program.
     *
     * @param pRulesUtilities
     * @param gtpInterface
     * @param udpInterface
     * @param qdisc_scheduler
     */
    void setup(
        std::shared_ptr<RulesUtilities> pRulesUtilities,
        const std::string& gtpInterface, 
        const std::string& udpInterface, 
        const char* qdisc_scheduler);
    /*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Set Members of the class UserPlaneComponent
     * 
     * @param pRulesUtilities 
     * @param gtpInterface 
     * @param udpInterface
    */
    void UserPlaneComponent::set_members(std::shared_ptr<RulesUtilities> pRulesUtilities,
    const std::string& gtpInterface, const std::string& udpInterface);
    
    /*---------------------------------------------------------------------------------------------------------------*/
        
    /**
     * @brief Tear down User Plane Component.
     * Tear down all programs that were setup.
     *
     */
    void tearDown();

    /*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Get the Session Manager object.
     *
     * @return std::shared_ptr<SessionManager> The session manager reference.
     */
    std::shared_ptr<SessionManager> getSessionManager() const;

    /*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Get the Rules Factory object.
     *
     * @return std::shared_ptr<RulesFactory> The rules factory reference.
     */
    std::shared_ptr<RulesUtilities> getRulesUtilities() const;

    /*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Get PFCP_Session_LookupProgram object.
     *
     * @return std::shared_ptr<PFCP_Session_LookupProgram> The
     * PFCP_Session_LookupProgram reference.
     */
    std::shared_ptr<PFCP_Session_LookupProgram> getPFCP_Session_LookupProgram()
        const;

    /*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Get the GTP interface.
     *
     * @return std::string The GTP interface.
     */
    std::string getGTPInterface() const;

    /*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Get UDP interface.
     *
     * @return std::string The UDP interface.
     */
    std::string getUDPInterface() const;
 
    /*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Get qdisc scheduler.
     *
     * @return const char*  qdisc scheduler name insid Linux Kernel (default: HTB).
     */
    const char* getQdiscScheduler() const;    

  /*---------------------------------------------------------------------------------------------------------------*/
  // From onNewSessionProgramObserver.
  void onNewSessionProgram(
      u_int32_t programId, u_int32_t fileDescriptor) override;

  /*---------------------------------------------------------------------------------------------------------------*/
  // From onNewSessionProgramObserver.
  void onDestroySessionProgram(u_int32_t programId) override;

  // TODO: getSessionManger?

 
    private:
    /**
     * @brief Construct a new User Plane Component object.
     *
     * @param pRulesUtilities the wrapper for rules (PDR, FAR).
     */
    UserPlaneComponent();

  // Log function for libbpf. Do not used it!!
    static int printLibbpfLog(
      enum libbpf_print_level lvl, const char* fmt, va_list args);

    /*------------------------------------------------------------------------------------------------------------------*/

    /**
     * @brief Create a qdisc object
     * 
     * @param sock 
     * @return struct rtnl_qdisc* 
     */
    struct rtnl_qdisc* create_qdisc(struct nl_sock *sock);
    
    /*------------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Intialize the qdisc parameters
     * 
     * @param std::string interface
     */
    void initializeQdisc(std::string interface);

    /*------------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Configure the root qdisc with HTB scheduler
     * 
     * @param qdisc 
     * @param htb_class 
     * @return struct rtnl_qdisc* 
     */
      struct rtnl_qdisc* configure_qdisc(struct rtnl_qdisc *qdisc, struct rtnl_class *htb_class);                   
    /*------------------------------------------------------------------------------------------------------------------*/

  // The session manager reference.
  std::shared_ptr<SessionManager> mpSessionManager;

  // The rules factory reference.
  std::shared_ptr<RulesUtilities> mpRulesUtilities;

  // The PFCP_Session_LookupProgram (BPF program entry point) reference.
  std::shared_ptr<PFCP_Session_LookupProgram> mpPFCP_Session_LookupProgram;

  // The PFCP_Session_PDR_LookupProgram (BPF program for PFCP Session)
  // reference.
  std::shared_ptr<PFCP_Session_PDR_LookupProgram>
      mpPFCP_Session_PDR_LookupProgram;

  // The GTP interface.
  std::string mGTPInterface;

  // The UDP interface.
  std::string mUDPInterface;

/*---------------------------------------------------------------------------------------------------------------*/
  const char *mQdiscScheduler;
  struct qdisc_params *qdisc_att;
  struct rtnl_qdisc *root_qdisc;
};

#endif  // __USERPLANECOMPONENT_H__
