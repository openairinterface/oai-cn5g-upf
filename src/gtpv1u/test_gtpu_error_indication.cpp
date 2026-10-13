/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 *
 * Self-check for the GTP-U header framing, and for the Error Indication in
 * particular. Header-only, but the project's own fmt/spdlog are needed, so it
 * builds inside the UPF builder image rather than on the host:
 *
 *   docker build --target oai-upf-builder -f docker/Dockerfile.upf.ubuntu \
 *       -t upf-builder .
 *   docker run --rm -v "$PWD":/src:ro upf-builder bash -c \
 *     'cd /src && g++ -std=c++17 $(for d in $(find src -type d \
 *        | grep -vE "kernel|bpf"); do echo -n "-I$d "; done) \
 *        src/gtpv1u/test_gtpu_error_indication.cpp -o /tmp/t -lfmt && /tmp/t'
 *
 * Two rules from TS 29.281 §5.1 are pinned here:
 *
 *  - "For Error Indication the S flag shall be set to '1'", with the header
 *    TEID all zeros (the failed TEID travels in the TEID Data I IE).
 *  - Sequence Number, N-PDU Number and Next Extension Header Type are one
 *    4-octet block: if any of S/PN/E is set, all three are present. Emitting
 *    only the field whose flag was set puts a 10-octet header on the wire and
 *    the peer then reads two bytes of the first IE as N-PDU/Next-Ext.
 */

#include <cassert>
#include <cstdio>
#include <sstream>
#include <string>

#include "3gpp_29.281.hpp"

using namespace gtpv1u;

namespace {

constexpr std::size_t MANDATORY = 8;  ///< bytes before the optional block
constexpr std::size_t OPTIONAL  = 4;  ///< seq(2) + npdu(1) + next-ext(1)
constexpr uint8_t S_FLAG        = 0x02;

std::string encode(gtpv1u_msg_header& h) {
  std::ostringstream os(std::ostringstream::binary);
  h.dump_to(os);
  return os.str();
}

}  // namespace

int main() {
  // --- an Error Indication header, as the constructor now builds it --------
  {
    gtpv1u_msg_header h;
    h.set_message_type(GTPU_ERROR_INDICATION);
    h.set_teid(0);
    h.set_sequence_number(
        0);  // what gtpv1u_msg(const gtpv1u_error_indication&) does

    const std::string b = encode(h);

    assert(b.size() == MANDATORY + OPTIONAL);         // 12, not 10
    assert((uint8_t) b[0] & S_FLAG);                  // S = 1
    assert((uint8_t) b[1] == GTPU_ERROR_INDICATION);  // type 26
    // TEID all zeros; the failed TEID is carried in the TEID Data I IE.
    for (int i = 4; i < 8; i++) assert(b[i] == 0);
    // The length field counts everything after the mandatory 8 octets, so it
    // has to include the whole optional block -- it used to count only 2.
    const uint16_t len = (uint16_t) (((uint8_t) b[2] << 8) | (uint8_t) b[3]);
    assert(len == OPTIONAL);
  }

  // --- the block is indivisible, whichever flag put it there ---------------
  {
    gtpv1u_msg_header h;
    h.set_message_type(GTPU_ECHO_REQUEST);
    h.set_sequence_number(0x1234);
    const std::string b = encode(h);
    assert(b.size() == MANDATORY + OPTIONAL);
    assert((uint8_t) b[8] == 0x12 && (uint8_t) b[9] == 0x34);  // big endian
    assert((uint8_t) b[10] == 0 && (uint8_t) b[11] == 0);      // npdu, next-ext
  }

  // --- with no flag set the header stays at the mandatory 8 ----------------
  {
    gtpv1u_msg_header h;
    h.set_message_type(GTPU_G_PDU);
    h.set_teid(0x0102'0304);
    const std::string b = encode(h);
    assert(b.size() == MANDATORY);
    assert(((uint8_t) b[0] & S_FLAG) == 0);
  }

  // --- what dump_to() writes, load_from() must read back -------------------
  // The two used to disagree: both wrote/read the sequence number on S, but
  // the other two octets only on E or PN. A round trip is what catches that.
  {
    gtpv1u_msg_header out;
    out.set_message_type(GTPU_ERROR_INDICATION);
    out.set_teid(0);
    out.set_sequence_number(0xABCD);
    const std::string b = encode(out);

    std::istringstream is(b, std::istringstream::binary);
    gtpv1u_msg_header in;
    in.load_from(is);

    assert(in.get_message_type() == GTPU_ERROR_INDICATION);
    assert(in.get_teid() == 0);
    uint16_t sn = 0;
    assert(in.get_sequence_number(sn) && sn == 0xABCD);
    // Every octet consumed: nothing left for the IE decoder to trip over.
    assert(is.tellg() == (std::streampos) b.size());
    // And the IE length it derives is zero here, not -2.
    assert(in.get_message_length_wo_xheader() == 0);
  }

  printf("test_gtpu_error_indication: all checks passed\n");
  return 0;
}
