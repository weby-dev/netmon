// SPDX-License-Identifier: GPL-2.0
#include "net_util.h"
#include <arpa/inet.h>
#include <cstdio>

namespace netmon {

std::string ip_to_string(const uint8_t addr[16], uint8_t family) {
    char buf[INET6_ADDRSTRLEN] = {0};
    if (family == AF_INET) {
        inet_ntop(AF_INET, addr, buf, sizeof(buf));
    } else {
        inet_ntop(AF_INET6, addr, buf, sizeof(buf));
    }
    return std::string(buf);
}

const char* proto_name(uint8_t proto) {
    switch (proto) {
    case IPPROTO_TCP:    return "TCP";
    case IPPROTO_UDP:    return "UDP";
    case IPPROTO_ICMP:   return "ICMP";
    case IPPROTO_ICMPV6: return "ICMPv6";
    default:             return "OTHER";
    }
}

bool Cidr::parse(const std::string& s, Cidr& out) {
    auto slash = s.find('/');
    if (slash == std::string::npos) return false;
    std::string ip = s.substr(0, slash);
    int prefix = std::atoi(s.substr(slash + 1).c_str());

    std::memset(&out, 0, sizeof(out));
    if (ip.find(':') != std::string::npos) {
        if (inet_pton(AF_INET6, ip.c_str(), out.addr) != 1) return false;
        out.family = AF_INET6;
        out.prefix = (uint8_t)(prefix < 0 ? 0 : (prefix > 128 ? 128 : prefix));
    } else {
        if (inet_pton(AF_INET, ip.c_str(), out.addr) != 1) return false;
        out.family = AF_INET;
        out.prefix = (uint8_t)(prefix < 0 ? 0 : (prefix > 32 ? 32 : prefix));
    }
    return true;
}

bool Cidr::contains(const uint8_t a[16], uint8_t fam) const {
    if (fam != family) return false;
    int full = prefix / 8;
    int rem  = prefix % 8;
    for (int i = 0; i < full; ++i)
        if (a[i] != addr[i]) return false;
    if (rem) {
        uint8_t mask = (uint8_t)(0xFF << (8 - rem));
        if ((a[full] & mask) != (addr[full] & mask)) return false;
    }
    return true;
}

CidrSet::CidrSet(const std::vector<std::string>& cidrs) {
    for (const auto& s : cidrs) {
        Cidr c;
        if (Cidr::parse(s, c)) nets_.push_back(c);
    }
}

bool CidrSet::contains(const uint8_t a[16], uint8_t fam) const {
    for (const auto& n : nets_)
        if (n.contains(a, fam)) return true;
    return false;
}

bool flow_is_forward(const flow_key& k) {
    int c = std::memcmp(k.src_addr, k.dst_addr, 16);
    if (c != 0) return c < 0;
    return ntoh16(k.src_port) <= ntoh16(k.dst_port);
}

flow_key flow_reverse(const flow_key& k) {
    flow_key r = k;
    std::memcpy(r.src_addr, k.dst_addr, 16);
    std::memcpy(r.dst_addr, k.src_addr, 16);
    r.src_port = k.dst_port;
    r.dst_port = k.src_port;
    return r;
}

} // namespace netmon
