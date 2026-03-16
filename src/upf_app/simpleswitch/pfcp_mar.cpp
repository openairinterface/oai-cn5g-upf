/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     Boy Scout cleanup — Doxygen, 3GPP §-refs.
 *              V17.10.0 harmonisation: spec version updated; status comment
 *              updated to reflect create_mar / update_mar implementation gap
 *              and new V17.10.0 IEs (Thresholds §8.2.196, Steering Mode
 *              Indicator §8.2.197).
 *              IE table in pfcp_mar.hpp reformatted: unified column layout
 *              with Sxa/Sxb/Sxc/N4 applicability and Table(s) cross-reference
 *              column, consistent with pfcp_bar.hpp and pfcp_urr.hpp.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 */

/*! \file pfcp_mar.cpp
   \author  Franck MESSAOUDI
   \date 2026
   \email: franck.messaoudi@eurecom.fr

   create_mar and update_mar are not yet implemented in the OAI PFCP
   library (msg_pfcp.hpp — IE codes 165/169 defined in 3gpp_29_244.h
   but no corresponding class in msg_pfcp.hpp or 3gpp_29_244.hpp).

   Until those are added, pfcp_mar objects are populated via direct
   set() / set_3gpp_access() / set_non3gpp_access() calls in
   SessionProgramManager when handling PFCP Session-Establishment and
   Session-Modification requests.

   V17.10.0 adds two new conditional IEs that are also not yet in the
   OAI lib and are not forwarded to the kernel BPF map:
     - Thresholds             §8.2.196  IE type 288
     - Steering Mode Indicator §8.2.197 IE type 289
   Both are stored in pfcp_mar for session state tracking. See TODO
   markers in pfcp_mar.hpp field declarations and in ConvertMar().

   There is no update() method: per 3GPP TS 29.244 V17.10.0 Table
   7.5.4.16-1, Update MAR carries individual IE updates including
   Update 3GPP/Non-3GPP Access Forwarding Action Information (IE types
   175/176, Tables 7.5.4.16-2/3). These are not yet implemented in the
   OAI lib. Until then, MAR updates are handled via Remove MAR
   (Table 7.5.4.15-1) + Create MAR.
*/

#include "pfcp_mar.hpp"

// All methods are defined inline in pfcp_mar.hpp.
// This file exists to satisfy the build system and document the
// implementation status of create_mar / update_mar serialization.
