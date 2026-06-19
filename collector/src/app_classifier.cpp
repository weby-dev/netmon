// SPDX-License-Identifier: GPL-2.0
#include "app_classifier.h"
#include <unordered_map>

extern "C" {
#include "common.h"
}

namespace netmon {

const char* app_category_name(AppCategory c) {
    switch (c) {
    case AppCategory::Web:          return "web";
    case AppCategory::WebSecure:    return "web-tls";
    case AppCategory::Dns:          return "dns";
    case AppCategory::Mail:         return "mail";
    case AppCategory::Database:     return "database";
    case AppCategory::Cache:        return "cache";
    case AppCategory::Ssh:          return "ssh";
    case AppCategory::Rdp:          return "rdp";
    case AppCategory::FileTransfer: return "file-transfer";
    case AppCategory::Voip:         return "voip";
    case AppCategory::Monitoring:   return "monitoring";
    case AppCategory::ProxmoxMgmt:  return "proxmox";
    case AppCategory::Other:        return "other";
    default:                        return "unknown";
    }
}

namespace {
struct Svc { const char* name; AppCategory cat; };

// Well-known service ports. Keyed on the service-side port.
const std::unordered_map<uint16_t, Svc>& tcp_table() {
    static const std::unordered_map<uint16_t, Svc> t = {
        {20,   {"ftp-data", AppCategory::FileTransfer}},
        {21,   {"ftp",      AppCategory::FileTransfer}},
        {22,   {"ssh",      AppCategory::Ssh}},
        {23,   {"telnet",   AppCategory::Other}},
        {25,   {"smtp",     AppCategory::Mail}},
        {53,   {"dns",      AppCategory::Dns}},
        {80,   {"http",     AppCategory::Web}},
        {110,  {"pop3",     AppCategory::Mail}},
        {143,  {"imap",     AppCategory::Mail}},
        {389,  {"ldap",     AppCategory::Other}},
        {443,  {"https",    AppCategory::WebSecure}},
        {465,  {"smtps",    AppCategory::Mail}},
        {587,  {"submission", AppCategory::Mail}},
        {636,  {"ldaps",    AppCategory::Other}},
        {993,  {"imaps",    AppCategory::Mail}},
        {995,  {"pop3s",    AppCategory::Mail}},
        {1433, {"mssql",    AppCategory::Database}},
        {1521, {"oracle",   AppCategory::Database}},
        {3306, {"mysql",    AppCategory::Database}},
        {3389, {"rdp",      AppCategory::Rdp}},
        {5432, {"postgresql", AppCategory::Database}},
        {5900, {"vnc",      AppCategory::Rdp}},
        {6379, {"redis",    AppCategory::Cache}},
        {8006, {"proxmox-web", AppCategory::ProxmoxMgmt}},
        {8007, {"pbs-web",  AppCategory::ProxmoxMgmt}},
        {8080, {"http-alt", AppCategory::Web}},
        {8443, {"https-alt",AppCategory::WebSecure}},
        {9090, {"cockpit",  AppCategory::Monitoring}},
        {9100, {"node-exporter", AppCategory::Monitoring}},
        {11211,{"memcached",AppCategory::Cache}},
        {27017,{"mongodb",  AppCategory::Database}},
    };
    return t;
}

const std::unordered_map<uint16_t, Svc>& udp_table() {
    static const std::unordered_map<uint16_t, Svc> t = {
        {53,   {"dns",      AppCategory::Dns}},
        {67,   {"dhcp",     AppCategory::Other}},
        {68,   {"dhcp",     AppCategory::Other}},
        {123,  {"ntp",      AppCategory::Other}},
        {161,  {"snmp",     AppCategory::Monitoring}},
        {500,  {"isakmp",   AppCategory::Other}},
        {514,  {"syslog",   AppCategory::Monitoring}},
        {1194, {"openvpn",  AppCategory::Other}},
        {3478, {"stun",     AppCategory::Voip}},
        {5060, {"sip",      AppCategory::Voip}},
        {5061, {"sips",     AppCategory::Voip}},
        {51820,{"wireguard",AppCategory::Other}},
    };
    return t;
}
} // namespace

AppInfo classify_app(uint8_t protocol, uint16_t s, uint16_t d) {
    const std::unordered_map<uint16_t, Svc>* tbl = nullptr;
    if (protocol == IPPROTO_TCP) tbl = &tcp_table();
    else if (protocol == IPPROTO_UDP) tbl = &udp_table();

    if (tbl) {
        // Prefer the smaller (well-known) port as the service side, but try
        // both so ephemeral->service and service->ephemeral both resolve.
        uint16_t lo = s < d ? s : d;
        uint16_t hi = s < d ? d : s;
        auto it = tbl->find(lo);
        if (it != tbl->end()) return {it->second.name, it->second.cat};
        it = tbl->find(hi);
        if (it != tbl->end()) return {it->second.name, it->second.cat};
    }

    if (protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6)
        return {"icmp", AppCategory::Other};

    return {"unknown", AppCategory::Unknown};
}

} // namespace netmon
