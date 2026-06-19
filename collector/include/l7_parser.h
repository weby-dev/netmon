// SPDX-License-Identifier: GPL-2.0
#pragma once
#include <cstdint>
#include <string>

extern "C" {
#include "common.h"
}

namespace netmon {

// Result of parsing an L7 payload sample captured by the XDP program.
struct L7Record {
    uint64_t    ts_ns = 0;
    std::string src_ip;
    std::string dst_ip;
    uint16_t    src_port = 0;
    uint16_t    dst_port = 0;
    std::string proto;        // "TCP"/"UDP"
    std::string l7_proto;     // "http"/"tls"/"dns"/"smtp"/"db"

    // Extracted fields (whichever apply to l7_proto).
    std::string http_method;
    std::string http_host;    // Host: header
    std::string http_path;
    std::string http_user_agent;
    std::string http_status;  // for responses

    std::string tls_sni;      // ClientHello SNI
    std::string tls_version;

    std::string dns_qname;    // first question name
    std::string dns_qtype;
    std::string dns_response; // first A/AAAA answer if present

    std::string smtp_command; // EHLO/MAIL/RCPT/banner
    std::string db_system;    // mysql / postgresql / mongodb / redis
    std::string db_query;     // best-effort first statement (redis/pg startup)

    bool valid = false;       // set true if anything was extracted
};

// Parse a raw kernel l7_event into a structured record. Never throws; on an
// unrecognised payload returns a record with valid=false but addresses filled.
L7Record parse_l7(const l7_event* ev);

} // namespace netmon
