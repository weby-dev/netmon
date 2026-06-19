// SPDX-License-Identifier: GPL-2.0
#pragma once
#include <cstdint>
#include <string>

namespace netmon {

// Coarse application category for bandwidth-per-application accounting.
enum class AppCategory {
    Unknown, Web, WebSecure, Dns, Mail, Database, Cache,
    Ssh, Rdp, FileTransfer, Voip, Monitoring, ProxmoxMgmt, Other
};

const char* app_category_name(AppCategory c);

// Map a (protocol, src_port, dst_port) tuple to an application name and
// category using a well-known-port table. The "service" port (the lower /
// well-known side) wins. Ports are in HOST byte order.
struct AppInfo {
    std::string  name;       // e.g. "https", "mysql", "proxmox-web"
    AppCategory  category;
};

AppInfo classify_app(uint8_t protocol, uint16_t src_port_host, uint16_t dst_port_host);

} // namespace netmon
