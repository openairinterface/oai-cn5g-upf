/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "async_shell_cmd.hpp"
#include "logger.hpp"
#include "upf_config.hpp"

using namespace oai::config;

namespace oai::config {

//------------------------------------------------------------------------------
int upf_config::execute() {
  return RETURNok;
}

//------------------------------------------------------------------------------
int upf_config::get_pfcp_node_id(pfcp::node_id_t& node_id) {
  node_id = {};
  if (fqdn.length() >= 3) {
    node_id.node_id_type = pfcp::NODE_ID_TYPE_FQDN;
    node_id.fqdn         = fqdn;
    return RETURNok;
  }
  if (n4.addr4.s_addr) {
    node_id.node_id_type    = pfcp::NODE_ID_TYPE_IPV4_ADDRESS;
    node_id.u1.ipv4_address = n4.addr4;
    return RETURNok;
  }
  if (n4.addr6.s6_addr32[0] | n4.addr6.s6_addr32[1] | n4.addr6.s6_addr32[2] |
      n4.addr6.s6_addr32[3]) {
    node_id.node_id_type    = pfcp::NODE_ID_TYPE_IPV6_ADDRESS;
    node_id.u1.ipv6_address = n4.addr6;
    return RETURNok;
  }
  return RETURNerror;
}

//------------------------------------------------------------------------------
int upf_config::get_pfcp_fseid(pfcp::fseid_t& fseid) {
  int rc = RETURNerror;
  fseid  = {};
  if (n4.addr4.s_addr) {
    fseid.v4           = 1;
    fseid.ipv4_address = n4.addr4;
    rc                 = RETURNok;
  }
  if (n4.addr6.s6_addr32[0] | n4.addr6.s6_addr32[1] | n4.addr6.s6_addr32[2] |
      n4.addr6.s6_addr32[3]) {
    fseid.v6           = 1;
    fseid.ipv6_address = n4.addr6;
    rc                 = RETURNok;
  }
  return rc;
}
}  // namespace oai::config
