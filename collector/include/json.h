// SPDX-License-Identifier: GPL-2.0
// Minimal single-line JSON builder used by both the ClickHouse writer (one
// object per row, JSONEachRow) and the live stream server.
#pragma once
#include <string>
#include <cstdio>
#include <cstdint>

namespace netmon {

inline std::string json_escape(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (char c : in) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if ((unsigned char)c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", (unsigned)(unsigned char)c);
                out += buf;
            } else {
                out += c;
            }
        }
    }
    return out;
}

// Builds a single JSON object: {"k":"v","n":123,...}
struct JsonRow {
    std::string s = "{";
    bool first = true;
    void sep() { if (!first) s += ','; first = false; }
    JsonRow& str(const char* k, const std::string& v) {
        sep(); s += '"'; s += k; s += "\":\""; s += json_escape(v); s += '"'; return *this;
    }
    JsonRow& num(const char* k, uint64_t v) {
        sep(); s += '"'; s += k; s += "\":"; s += std::to_string(v); return *this;
    }
    JsonRow& inum(const char* k, int64_t v) {
        sep(); s += '"'; s += k; s += "\":"; s += std::to_string(v); return *this;
    }
    JsonRow& dbl(const char* k, double v) {
        sep(); s += '"'; s += k; s += "\":";
        char buf[40]; std::snprintf(buf, sizeof(buf), "%.3f", v); s += buf; return *this;
    }
    std::string done() { s += '}'; return s; }
};

// Builds a JSON array of objects: [{...},{...}]
struct JsonArr {
    std::string s = "[";
    bool first = true;
    void add(const std::string& obj) { if (!first) s += ','; first = false; s += obj; }
    std::string done() { s += ']'; return s; }
};

} // namespace netmon
