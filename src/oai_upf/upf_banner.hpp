/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <cstdio>
#include <unistd.h>

#define _OB "\033[94m"    // OAI ▓ fill       — bright blue
#define _OW "\033[97m"    // OAI ╗╔║╚╝═        — bright white
#define _UG "\033[92m"    // UPF ▓ (green)     — bright green
#define _UW "\033[97m"    // UPF ▓ (contour)   — bright white
#define _V3 "\033[33m"    // v3.0 / copyright  — amber
#define _CY "\033[96m"    // OpenAirInterface  — cyan
#define _MT "\033[37m"    // 3GPP meta         — gray
#define _DM "\033[2;37m"  // separator / dots  — dim
#define _RS "\033[0m"     // reset

// ▓▓ replaces ██ everywhere — forces pixel-art spacing in all fonts
#define _BANNER_COLOR                                                          \
  "\n"                                                                         \
  "                  " _OB "▓▓▓▓▓▓" _OW "╗  " _OB "▓▓▓▓▓" _OW "╗ " _OB         \
  "▓▓" _OW "╗  " _UG "▓▓  " _UW "▓▓  " _UW "▓▓" _UG "▓▓▓▓  " _UG "▓▓" _UW      \
  "▓▓" _UG "▓▓" _UW "▓▓" _RS                                                   \
  "\n"                                                                         \
  "                 " _OB "▓▓" _OW "╔═══" _OB "▓▓" _OW "╗" _OB "▓▓" _OW        \
  "╔══" _OB "▓▓" _OW "╗" _OB "▓▓" _OW "║  " _UW "▓▓  " _UG "▓▓  " _UG          \
  "▓▓  " _UW "▓▓  " _UG "▓▓      " _RS                                         \
  "\n"                                                                         \
  "                 " _OB "▓▓" _OW "║   " _OB "▓▓" _OW "║" _OB "▓▓▓▓▓▓▓" _OW   \
  "║" _OB "▓▓" _OW "║  " _UG "▓▓  " _UW "▓▓  " _UW "▓▓" _UG "▓▓▓▓  " _UG       \
  "▓▓▓▓" _UW "▓▓  " _RS                                                        \
  "\n"                                                                         \
  "                 " _OB "▓▓" _OW "║   " _OB "▓▓" _OW "║" _OB "▓▓" _OW        \
  "╔══" _OB "▓▓" _OW "║" _OB "▓▓" _OW "║  " _UW "▓▓  " _UG "▓▓  " _UG          \
  "▓▓      " _UW "▓▓      " _RS                                                \
  "\n"                                                                         \
  "                 " _OW "╚" _OB "▓▓▓▓▓▓" _OW "╔╝" _OB "▓▓" _OW "║  " _OB     \
  "▓▓" _OW "║" _OB "▓▓" _OW "║  " _UG "▓▓" _UW "▓▓" _UG "▓▓  " _UG             \
  "▓▓      " _UW "▓▓  " _V3 "v3.0" _RS                                         \
  "\n"                                                                         \
  "                  " _OW "╚═════╝ ╚═╝  ╚═╝╚═╝" _RS                           \
  "\n"                                                                         \
  "                 " _DM                                                      \
  "───────────────────────────────────────────────────────────────" _RS        \
  "\n"                                                                         \
  "                 " _CY "OpenAirInterface" _DM "  ·  " _UG                   \
  "User Plane Function" _DM "  ·  " _UG "5G Core · N4" _RS                     \
  "\n"                                                                         \
  "                 " _MT                                                      \
  "3GPP TS 29.244  ·  PFCP V17.10.0  ·  Release 17" _RS                        \
  "\n"                                                                         \
  "                 " _V3 "© OpenAirInterface Software Alliance" _RS           \
  "\n"                                                                         \
  "\n"

#define _BANNER_PLAIN                                                                                                                                                                      \
  "\n"                                                                                                                                                                                     \
  "                   ██████╗  █████╗ ██╗  ██  ██  ██████  ████████\n"                                                 \
  "                  ██╔═══██╗██╔══██╗██║  ██  ██  ██  ██  ██      \n"                                                         \
  "                  ██║   ██║███████║██║  ██  ██  ██████  ██████  \n"                                                   \
  "                  ██║   ██║██╔══██║██║  ██  ██  ██      ██      \n"                                                                   \
  "                  ╚██████╔╝██║  ██║██║  ██████  ██      ██  v3.0\n"                                                             \
  "                   ╚═════╝ ╚═╝  ╚═╝╚═╝\n"                                                                                                               \
  "                  "                                                                                                                                                                     \
  "────────────────────────────────────────────────────────────\n" \
  "                  OpenAirInterface  ·  User Plane Function  ·  5G Core · "                                                                                                           \
  "N4\n"                                                                                                                                                                                   \
  "                  3GPP TS 29.244  ·  PFCP V17.10.0  ·  Release 17\n"                                                                                                                  \
  "                  © OpenAirInterface Software Alliance\n"                                                                                                                              \
  "\n"

namespace oai::upf {

// clang-format off
 inline void print_banner() {
   //std::fputs(isatty(STDOUT_FILENO) ? _BANNER_COLOR : _BANNER_PLAIN, stdout);
 std::fputs(_BANNER_COLOR, stdout);
 }
// clang-format on

}  // namespace oai::upf

#undef _OB
#undef _OW
#undef _UG
#undef _UW
#undef _V3
#undef _CY
#undef _MT
#undef _DM
#undef _RS
#undef _BANNER_COLOR
#undef _BANNER_PLAIN
