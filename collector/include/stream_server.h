// SPDX-License-Identifier: GPL-2.0
//
// StreamServer - a tiny, dependency-free embedded HTTP/SSE server that pushes
// real-time JSON events from the collector straight to any consumer
// (your app, a browser EventSource, curl, ...), bypassing the database on the
// live path. There is NO GUI/dashboard - this is purely a machine-consumable
// event stream.
//
//   GET /live     -> text/event-stream, named SSE events:
//                    stats | ifaces | talkers | flows | l7 | security
//   GET /healthz  -> {"ok":true,"clients":N}
//
// Design: a single epoll reactor thread owns all sockets and per-client write
// buffers (so no per-client locking). Collector threads call broadcast(),
// which frames the message, pushes it onto a queue, and wakes the reactor via
// an eventfd. Slow clients that exceed the per-client buffer cap are dropped.
//
// Linux-only (epoll/eventfd/accept4) — same as the rest of the project.
#pragma once
#include <atomic>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace netmon {

class StreamServer {
public:
    StreamServer(const std::string& bind_addr, uint16_t port);
    ~StreamServer();

    StreamServer(const StreamServer&) = delete;
    StreamServer& operator=(const StreamServer&) = delete;

    bool start();
    void stop();

    // Push a named SSE event to every connected /live client.
    // `type` is the SSE event name; `json` must be a single line (no raw '\n').
    void broadcast(const char* type, const std::string& json);

    size_t client_count() const { return client_count_.load(); }

private:
    struct Client {
        int         fd = -1;
        std::string reqbuf;       // accumulates the HTTP request
        std::string outbuf;       // pending bytes to write
        bool        streaming = false;  // upgraded to SSE
        bool        want_close = false; // close once outbuf drained
        bool        epollout = false;   // currently watching EPOLLOUT
    };

    void run();                          // reactor loop
    void do_accept();
    void on_readable(int fd);
    void on_writable(int fd);
    void handle_request(Client& c);
    bool flush(Client& c);          // false => caller should close the client
    void update_interest(Client& c);
    void close_client(int fd);
    void drain_queue();

    std::string bind_addr_;
    uint16_t    port_;

    int listen_fd_ = -1;
    int epoll_fd_  = -1;
    int event_fd_  = -1;

    std::thread reactor_;
    std::atomic<bool>   running_{false};
    std::atomic<size_t> client_count_{0};

    std::unordered_map<int, Client> clients_;   // reactor-thread owned

    std::mutex              qmtx_;
    std::deque<std::string> queue_;             // framed SSE messages

    static constexpr size_t kMaxClientBuf = 8 * 1024 * 1024;  // drop if exceeded
    static constexpr size_t kMaxQueue     = 20000;            // cap backlog
};

} // namespace netmon
