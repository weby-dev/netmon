// SPDX-License-Identifier: GPL-2.0
//
// Deep-packet parsing of the small payload samples the XDP program captures.
// Everything here is strictly bounds-checked against the captured length so a
// truncated / malicious payload can never read out of bounds.
#include "l7_parser.h"
#include "net_util.h"
#include <cctype>
#include <cstring>
#include <string>

namespace netmon {

namespace {

inline std::string sv_lower(std::string s) {
    for (auto& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

// ---- HTTP --------------------------------------------------------------- //
bool parse_http(const uint8_t* p, size_t len, L7Record& r) {
    static const char* methods[] = {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ",
        "PATCH ", "CONNECT ", "TRACE "
    };
    std::string text(reinterpret_cast<const char*>(p),
                     len > L7_SNAP_LEN ? L7_SNAP_LEN : len);

    bool is_request = false;
    for (auto* m : methods) {
        if (text.rfind(m, 0) == 0) { is_request = true; break; }
    }
    bool is_response = text.rfind("HTTP/", 0) == 0;
    if (!is_request && !is_response) return false;

    // First line.
    auto eol = text.find("\r\n");
    std::string line = (eol == std::string::npos) ? text : text.substr(0, eol);

    if (is_request) {
        auto sp1 = line.find(' ');
        auto sp2 = (sp1 == std::string::npos) ? std::string::npos
                                              : line.find(' ', sp1 + 1);
        if (sp1 != std::string::npos) {
            r.http_method = line.substr(0, sp1);
            if (sp2 != std::string::npos)
                r.http_path = line.substr(sp1 + 1, sp2 - sp1 - 1);
        }
    } else {
        // "HTTP/1.1 200 OK"
        auto sp1 = line.find(' ');
        if (sp1 != std::string::npos) {
            auto sp2 = line.find(' ', sp1 + 1);
            r.http_status = line.substr(sp1 + 1,
                (sp2 == std::string::npos ? line.size() : sp2) - sp1 - 1);
        }
    }

    // Headers we care about.
    size_t pos = (eol == std::string::npos) ? text.size() : eol + 2;
    while (pos < text.size()) {
        auto next = text.find("\r\n", pos);
        std::string h = text.substr(pos, (next == std::string::npos ? text.size() : next) - pos);
        if (h.empty()) break;
        auto colon = h.find(':');
        if (colon != std::string::npos) {
            std::string name = sv_lower(h.substr(0, colon));
            size_t vstart = colon + 1;
            while (vstart < h.size() && h[vstart] == ' ') vstart++;
            std::string val = h.substr(vstart);
            if (name == "host") r.http_host = val;
            else if (name == "user-agent") r.http_user_agent = val;
        }
        if (next == std::string::npos) break;
        pos = next + 2;
    }

    r.l7_proto = "http";
    r.valid = true;
    return true;
}

// ---- TLS ClientHello SNI ------------------------------------------------ //
// Walks the TLS record -> Handshake -> ClientHello -> extensions to find SNI.
bool parse_tls(const uint8_t* p, size_t len, L7Record& r) {
    size_t i = 0;
    if (len < 5) return false;
    if (p[0] != 0x16) return false;             // handshake record
    uint16_t tls_ver = (uint16_t)((p[1] << 8) | p[2]);
    // record length p[3..4] — ignored, we bound on captured len.
    i = 5;
    if (i >= len || p[i] != 0x01) return false; // ClientHello
    // handshake length (3 bytes) at i+1..i+3
    i += 4;
    if (i + 2 > len) return false;
    i += 2;                                      // client_version
    if (i + 32 > len) return false;
    i += 32;                                     // random
    if (i >= len) return false;
    uint8_t sid_len = p[i]; i += 1 + sid_len;    // session id
    if (i + 2 > len) return false;
    uint16_t cs_len = (uint16_t)((p[i] << 8) | p[i + 1]); i += 2 + cs_len;
    if (i + 1 > len) return false;
    uint8_t comp_len = p[i]; i += 1 + comp_len;  // compression methods
    if (i + 2 > len) return false;
    uint16_t ext_total = (uint16_t)((p[i] << 8) | p[i + 1]); i += 2;
    size_t ext_end = i + ext_total;
    if (ext_end > len) ext_end = len;

    while (i + 4 <= ext_end) {
        uint16_t ext_type = (uint16_t)((p[i] << 8) | p[i + 1]);
        uint16_t ext_len  = (uint16_t)((p[i + 2] << 8) | p[i + 3]);
        i += 4;
        if (i + ext_len > ext_end) break;
        if (ext_type == 0x0000) {                // server_name
            size_t j = i;
            if (j + 2 > ext_end) break;
            j += 2;                              // server_name_list length
            if (j + 3 > ext_end) break;
            uint8_t name_type = p[j]; j += 1;
            uint16_t name_len = (uint16_t)((p[j] << 8) | p[j + 1]); j += 2;
            if (name_type == 0 && j + name_len <= ext_end) {
                r.tls_sni.assign(reinterpret_cast<const char*>(p + j), name_len);
            }
            break;
        }
        i += ext_len;
    }

    switch (tls_ver) {
        case 0x0301: r.tls_version = "TLS1.0"; break;
        case 0x0302: r.tls_version = "TLS1.1"; break;
        case 0x0303: r.tls_version = "TLS1.2"; break;
        case 0x0304: r.tls_version = "TLS1.3"; break;
        default:     r.tls_version = "TLS";     break;
    }
    r.l7_proto = "tls";
    r.valid = !r.tls_sni.empty();
    return r.valid;
}

// ---- DNS ---------------------------------------------------------------- //
std::string dns_qtype_name(uint16_t t) {
    switch (t) {
        case 1:  return "A";
        case 2:  return "NS";
        case 5:  return "CNAME";
        case 6:  return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 65: return "HTTPS";
        default: return std::to_string(t);
    }
}

bool parse_dns(const uint8_t* p, size_t len, L7Record& r) {
    if (len < 12) return false;
    uint16_t qdcount = (uint16_t)((p[4] << 8) | p[5]);
    if (qdcount == 0) return false;

    size_t i = 12;
    std::string name;
    int guard = 0;
    while (i < len && guard++ < 128) {
        uint8_t l = p[i++];
        if (l == 0) break;
        if ((l & 0xC0) == 0xC0) { i++; break; }  // compression pointer
        if (i + l > len) return false;
        if (!name.empty()) name += '.';
        for (uint8_t k = 0; k < l && i < len; ++k) {
            char c = (char)p[i++];
            name += (std::isprint((unsigned char)c) ? c : '?');
        }
    }
    if (name.empty()) return false;
    r.dns_qname = name;
    if (i + 2 <= len) {
        uint16_t qtype = (uint16_t)((p[i] << 8) | p[i + 1]);
        r.dns_qtype = dns_qtype_name(qtype);
    }
    r.l7_proto = "dns";
    r.valid = true;
    return true;
}

// ---- SMTP --------------------------------------------------------------- //
bool parse_smtp(const uint8_t* p, size_t len, L7Record& r) {
    std::string text(reinterpret_cast<const char*>(p),
                     len > 64 ? 64 : len);
    static const char* verbs[] = {"EHLO", "HELO", "MAIL", "RCPT", "DATA",
                                  "AUTH", "STARTTLS", "QUIT", "220 ", "250 "};
    for (auto* v : verbs) {
        if (text.rfind(v, 0) == 0) {
            auto eol = text.find("\r\n");
            r.smtp_command = (eol == std::string::npos) ? text : text.substr(0, eol);
            r.l7_proto = "smtp";
            r.valid = true;
            return true;
        }
    }
    return false;
}

// ---- Databases (best effort handshake fingerprints) --------------------- //
bool parse_db(const uint8_t* p, size_t len, L7Record& r) {
    // Redis inline / RESP commands are ASCII ("*1\r\n$4\r\nPING").
    if (len >= 4 && (p[0] == '*' || p[0] == '+' || p[0] == '$')) {
        r.db_system = "redis";
        std::string s(reinterpret_cast<const char*>(p),
                      len > 48 ? 48 : len);
        for (auto& c : s) if (c == '\r' || c == '\n') c = ' ';
        r.db_query = s;
        r.l7_proto = "db"; r.valid = true; return true;
    }
    // MySQL server greeting: [3-byte len][seq=0][protocol=10].
    if (len >= 5 && p[3] == 0x00 && p[4] == 0x0a) {
        r.db_system = "mysql"; r.l7_proto = "db"; r.valid = true; return true;
    }
    // PostgreSQL StartupMessage: [len:4][protocol 0x00030000].
    if (len >= 8 && p[4] == 0x00 && p[5] == 0x03 && p[6] == 0x00 && p[7] == 0x00) {
        r.db_system = "postgresql"; r.l7_proto = "db"; r.valid = true; return true;
    }
    // MongoDB wire: messageLength[4] requestID[4] responseTo[4] opCode[4].
    if (len >= 16) {
        uint32_t opcode = (uint32_t)(p[12] | (p[13] << 8) | (p[14] << 16) | (p[15] << 24));
        if (opcode == 2013 /*OP_MSG*/ || opcode == 2004 /*OP_QUERY*/) {
            r.db_system = "mongodb"; r.l7_proto = "db"; r.valid = true; return true;
        }
    }
    return false;
}

} // namespace

L7Record parse_l7(const l7_event* ev) {
    L7Record r;
    r.ts_ns    = ev->ts_ns;
    r.src_ip   = ip_to_string(ev->src_addr, ev->family);
    r.dst_ip   = ip_to_string(ev->dst_addr, ev->family);
    r.src_port = ntoh16(ev->src_port);
    r.dst_port = ntoh16(ev->dst_port);
    r.proto    = (ev->protocol == IPPROTO_UDP) ? "UDP" : "TCP";

    const uint8_t* p = ev->payload;
    size_t len = ev->payload_len;
    if (len > L7_SNAP_LEN) len = L7_SNAP_LEN;
    if (len == 0) return r;

    // Dispatch on the kernel's port-based hint, but fall through to other
    // parsers so e.g. HTTP on a non-standard port is still recognised.
    switch (ev->l7_hint) {
    case L7_DNS:  if (parse_dns(p, len, r)) return r;  break;
    case L7_TLS:  if (parse_tls(p, len, r)) return r;  break;
    case L7_HTTP: if (parse_http(p, len, r)) return r; break;
    case L7_SMTP: if (parse_smtp(p, len, r)) return r; break;
    case L7_DB:   if (parse_db(p, len, r)) return r;   break;
    default: break;
    }
    // Generic fallthrough.
    if (parse_http(p, len, r)) return r;
    if (parse_tls(p, len, r))  return r;
    if (ev->protocol == IPPROTO_UDP && parse_dns(p, len, r)) return r;
    return r;
}

} // namespace netmon
