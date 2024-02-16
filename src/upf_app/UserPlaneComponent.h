#ifndef __USERPLANECOMPONENT_H__
#define __USERPLANECOMPONENT_H__

#include <bpf/libbpf.h>  // enum libbpf_print_level
#include <memory>
#include <string>
#include <observer/OnStateChangeSessionProgramObserver.h>
#include <helpers/qdisc_parameters.h>

class SessionManager;
class NetlinkManager;
class RulesUtilities;
class PFCP_Session_LookupProgram;
class PFCP_Session_PDR_LookupProgram;


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
    void setMembers(std::shared_ptr<RulesUtilities> pRulesUtilities,
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
     * @brief Get the Netlink Manager object.
     *
     * @return std::shared_ptr<NetlinkManager> The Netlink manager reference.
     */
    std::shared_ptr<NetlinkManager> getNetlinkManager() const;

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
     * @brief Getter 
     *        Get the GTP interface.
     *
     * @return std::string The GTP interface.
     */
    std::string getGTPInterface() const;


  /*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Getter 
     *        Get UDP interface.
     *
     * @return std::string The UDP interface.
     */
    std::string getUDPInterface() const;
 

  /*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Getter
     *        Get root qdisc scheduler.
     *
     * @return const char*  qdisc scheduler name insid Linux Kernel (default: HTB).
     */
    const char* getRootQdiscScheduler() const;    
    
  /*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Getter
     *        Get the Root qdisc Quantum Value
     * 
     * @return uint32_t 
     */
    uint32_t getRootQdiscQuantum() const;
  
  /*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Getter
     *        Get defaultClass value
     * 
     * @return uint32_t 
     */
    uint32_t getRootQdiscDefaultClass() const; 


  /*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Getter
     *        Get root class scheduler.
     *
     * @return const char*  qdisc scheduler name insid Linux Kernel (default: HTB).
     */
    const char* getRootClassScheduler() const;    


  /*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Getter
     *        Get the Root Class Rate Value
     * 
     * @return uint32_t 
     */
    uint32_t getRootClassRate() const;
  

  /*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Get root class ceil value
     * 
     * @return uint32_t 
     */
    uint32_t getRootClassCeil() const; 


  /*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief What to Do on New SessionProgram
     * 
     * @param programId 
     * @param fileDescriptor 
     */
    void onNewSessionProgram(
        u_int32_t programId, u_int32_t fileDescriptor) override;


  /*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief What to Do when Destroying SessionProgram
     * 
     * @param programId 
     */
    void onDestroySessionProgram(u_int32_t programId) override;

  
 
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
     * @brief Setter 
     *        Retrieve parameters from NIC <Interface> 
     *        for the HTB class configuration
     * 
     * @param interface 
     * @return * void 
     */
    void setRootClassAttributes(std::string interface, const char *scheduler);
    
    
  /*------------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Setter 
     *        Set the Root Qdisc Parameters
     * 
     */
    void setRootQdiscAttributes(const char *scheduler); 


  /*------------------------------------------------------------------------------------------------------------------*/

    // The session manager reference.
    std::shared_ptr<SessionManager> mpSessionManager;

        // The netlink manager reference.
    std::shared_ptr<NetlinkManager> mpNetlinkManager;

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
    struct qdiscRootParams *qdiscAtt = nullptr;
    struct classParams *classAtt = nullptr;
    struct rtnl_qdisc *rootQdisc = nullptr;
    struct rtnl_class *rootClass = nullptr;
    
    struct nl_sock *sock;
    struct rtnl_link *link;
    //struct nl_cache *linkCache;
};

#endif  // __USERPLANECOMPONENT_H__
