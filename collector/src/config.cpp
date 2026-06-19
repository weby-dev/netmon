// SPDX-License-Identifier: GPL-2.0
#include "config.h"
#include <getopt.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace netmon {

void Config::print_usage(const char* prog) {
    std::fprintf(stderr,
"Usage: %s [options]\n"
"\n"
"  -i, --iface <name>         Interface to monitor (repeatable). On Proxmox,\n"
"                             pass the uplink (e.g. eno1) and each VM tap\n"
"                             (tapXXXiY) / veth for east-west visibility.\n"
"  -m, --mode <native|skb|hw> XDP attach mode (default: skb)\n"
"  -c, --clickhouse <url>     ClickHouse HTTP URL (default: http://127.0.0.1:8123)\n"
"  -d, --db <name>            ClickHouse database (default: netmon)\n"
"      --ch-user <user>       ClickHouse user (default: default)\n"
"      --ch-pass <pass>       ClickHouse password\n"
"  -t, --interval <sec>       Flow scrape interval (default: 2)\n"
"      --idle <sec>           Flow idle timeout (default: 30)\n"
"  -s, --stream-port <port>   Real-time SSE stream port (default: 8090)\n"
"      --stream-bind <addr>   Stream bind address (default: 0.0.0.0)\n"
"      --no-stream            Disable the real-time stream server\n"
"      --live-interval <sec>  Live KPI push cadence (default: 1)\n"
"      --ddos-pps <n>         DDoS packets/sec threshold (default: 50000)\n"
"      --ddos-syn <n>         DDoS SYN/sec threshold (default: 10000)\n"
"      --scan-ports <n>       Port-scan distinct-port threshold (default: 50)\n"
"      --scan-hosts <n>       Sweep distinct-host threshold (default: 50)\n"
"  -v, --verbose              Verbose logging\n"
"  -h, --help                 This help\n",
        prog);
}

Config Config::parse(int argc, char** argv) {
    Config c;

    enum {
        OPT_IDLE = 1000, OPT_DDOS_PPS, OPT_DDOS_SYN,
        OPT_SCAN_PORTS, OPT_SCAN_HOSTS, OPT_CH_USER, OPT_CH_PASS,
        OPT_NO_STREAM, OPT_STREAM_BIND, OPT_LIVE_INTERVAL
    };
    static const struct option longopts[] = {
        {"iface",       required_argument, nullptr, 'i'},
        {"mode",        required_argument, nullptr, 'm'},
        {"clickhouse",  required_argument, nullptr, 'c'},
        {"db",          required_argument, nullptr, 'd'},
        {"ch-user",     required_argument, nullptr, OPT_CH_USER},
        {"ch-pass",     required_argument, nullptr, OPT_CH_PASS},
        {"interval",    required_argument, nullptr, 't'},
        {"idle",        required_argument, nullptr, OPT_IDLE},
        {"stream-port", required_argument, nullptr, 's'},
        {"stream-bind", required_argument, nullptr, OPT_STREAM_BIND},
        {"no-stream",   no_argument,       nullptr, OPT_NO_STREAM},
        {"live-interval", required_argument, nullptr, OPT_LIVE_INTERVAL},
        {"ddos-pps",    required_argument, nullptr, OPT_DDOS_PPS},
        {"ddos-syn",    required_argument, nullptr, OPT_DDOS_SYN},
        {"scan-ports",  required_argument, nullptr, OPT_SCAN_PORTS},
        {"scan-hosts",  required_argument, nullptr, OPT_SCAN_HOSTS},
        {"verbose",     no_argument,       nullptr, 'v'},
        {"help",        no_argument,       nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };

    int ch;
    while ((ch = getopt_long(argc, argv, "i:m:c:d:t:s:vh", longopts, nullptr)) != -1) {
        switch (ch) {
        case 'i': c.interfaces.emplace_back(optarg); break;
        case 'm': c.xdp_mode = optarg; break;
        case 'c': c.clickhouse_url = optarg; break;
        case 'd': c.clickhouse_db = optarg; break;
        case OPT_CH_USER: c.clickhouse_user = optarg; break;
        case OPT_CH_PASS: c.clickhouse_pass = optarg; break;
        case 't': c.flow_poll_interval = std::atoi(optarg); break;
        case OPT_IDLE: c.flow_idle_timeout = std::atoi(optarg); break;
        case 's': c.stream_port = (uint16_t)std::atoi(optarg); break;
        case OPT_STREAM_BIND: c.stream_bind = optarg; break;
        case OPT_NO_STREAM: c.stream_enable = false; break;
        case OPT_LIVE_INTERVAL: c.live_interval = std::atoi(optarg); break;
        case OPT_DDOS_PPS: c.ddos_pps_threshold = std::strtoull(optarg, nullptr, 10); break;
        case OPT_DDOS_SYN: c.ddos_syn_threshold = std::strtoull(optarg, nullptr, 10); break;
        case OPT_SCAN_PORTS: c.scan_port_threshold = std::strtoul(optarg, nullptr, 10); break;
        case OPT_SCAN_HOSTS: c.scan_host_threshold = std::strtoul(optarg, nullptr, 10); break;
        case 'v': c.verbose = true; break;
        case 'h': print_usage(argv[0]); std::exit(0);
        default:  print_usage(argv[0]); std::exit(2);
        }
    }

    if (c.interfaces.empty()) {
        std::fprintf(stderr, "error: at least one --iface is required\n\n");
        print_usage(argv[0]);
        std::exit(2);
    }
    return c;
}

} // namespace netmon
