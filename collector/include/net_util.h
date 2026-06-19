// SPDX-License-Identifier: GPL-2.0
#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <array>
#include <functional>

extern "C" {
#include "common.h"
}

namespace netmon {

// Pretty-print a 16-byte address blob given the family.
std::string ip_to_string(const uint8_t addr[16], uint8_t family);

// Host-order port from a network-order 16-bit value.
inline uint16_t ntoh16(uint16_t v) {
    return (uint16_t)((v >> 8) | (v << 8));
}

// A parsed CIDR for internal/external classification (v4 and v6).
struct Cidr {
    uint8_t  family;        // AF_INET / AF_INET6
    uint8_t  addr[16];
    uint8_t  prefix;        // bits

    bool contains(const uint8_t a[16], uint8_t fam) const;
    static bool parse(const std::string& s, Cidr& out);
};

class CidrSet {
public:
    explicit CidrSet(const std::vector<std::string>& cidrs);
    bool contains(const uint8_t a[16], uint8_t fam) const;
private:
    std::vector<Cidr> nets_;
};

// Hashable / comparable key wrapper so flow_key can live in unordered_map.
struct FlowKeyHash {
    size_t operator()(const flow_key& k) const noexcept {
        // FNV-1a over the packed key bytes.
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&k);
        size_t h = 1469598103934665603ull;
        for (size_t i = 0; i < sizeof(flow_key); ++i) {
            h ^= p[i];
            h *= 1099511628211ull;
        }
        return h;
    }
};
struct FlowKeyEq {
    bool operator()(const flow_key& a, const flow_key& b) const noexcept {
        return std::memcmp(&a, &b, sizeof(flow_key)) == 0;
    }
};

// Canonical 5-tuple direction: returns true if the key is in "forward"
// orientation (lower endpoint first). Used to merge bidirectional flows.
bool flow_is_forward(const flow_key& k);

// Produce the reversed key (swap src/dst addr+port) for bidi merging.
flow_key flow_reverse(const flow_key& k);

const char* proto_name(uint8_t proto);

} // namespace netmon
