// SPDX-License-Identifier: GPL-2.0
#ifndef _GNU_SOURCE
#define _GNU_SOURCE          // accept4(), SOCK_NONBLOCK, eventfd, EFD_* on Linux
#endif
#include "stream_server.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <cstdio>
#include <sstream>
#include <vector>

namespace netmon {

static bool set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    return fl != -1 && fcntl(fd, F_SETFL, fl | O_NONBLOCK) == 0;
}

StreamServer::StreamServer(const std::string& bind_addr, uint16_t port)
    : bind_addr_(bind_addr), port_(port) {}

StreamServer::~StreamServer() { stop(); }

bool StreamServer::start() {
    listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) { perror("socket"); return false; }

    int one = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    if (inet_pton(AF_INET, bind_addr_.c_str(), &addr.sin_addr) != 1)
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listen_fd_, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(listen_fd_); listen_fd_ = -1; return false;
    }
    if (listen(listen_fd_, 128) < 0) {
        perror("listen"); close(listen_fd_); listen_fd_ = -1; return false;
    }
    set_nonblock(listen_fd_);

    epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd_ < 0) { perror("epoll_create1"); return false; }

    event_fd_ = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (event_fd_ < 0) { perror("eventfd"); return false; }

    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd_;
    epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, listen_fd_, &ev);
    ev.data.fd = event_fd_;
    epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, event_fd_, &ev);

    running_ = true;
    reactor_ = std::thread([this] { run(); });
    std::fprintf(stderr, "stream server listening on %s:%u (SSE /live)\n",
                 bind_addr_.c_str(), port_);
    return true;
}

void StreamServer::stop() {
    if (!running_.exchange(false)) return;
    // Wake the reactor so it can exit.
    uint64_t one = 1;
    if (event_fd_ >= 0) { ssize_t n = write(event_fd_, &one, sizeof(one)); (void)n; }
    if (reactor_.joinable()) reactor_.join();
    for (auto& [fd, c] : clients_) close(fd);
    clients_.clear();
    if (listen_fd_ >= 0) close(listen_fd_);
    if (epoll_fd_ >= 0)  close(epoll_fd_);
    if (event_fd_ >= 0)  close(event_fd_);
    listen_fd_ = epoll_fd_ = event_fd_ = -1;
}

void StreamServer::broadcast(const char* type, const std::string& json) {
    if (client_count_.load() == 0) return;        // nobody listening

    std::string frame;
    frame.reserve(json.size() + 32);
    frame += "event: ";
    frame += type;
    frame += "\ndata: ";
    frame += json;
    frame += "\n\n";

    {
        std::lock_guard<std::mutex> lk(qmtx_);
        if (queue_.size() >= kMaxQueue) queue_.pop_front();   // drop oldest
        queue_.push_back(std::move(frame));
    }
    uint64_t one = 1;
    ssize_t n = write(event_fd_, &one, sizeof(one));
    (void)n;
}

void StreamServer::run() {
    constexpr int kMaxEvents = 64;
    epoll_event events[kMaxEvents];

    while (running_.load()) {
        int n = epoll_wait(epoll_fd_, events, kMaxEvents, 1000);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            uint32_t e = events[i].events;

            if (fd == listen_fd_) {
                do_accept();
            } else if (fd == event_fd_) {
                uint64_t v;
                while (read(event_fd_, &v, sizeof(v)) > 0) {}   // drain
                drain_queue();
            } else {
                if (e & (EPOLLHUP | EPOLLERR)) { close_client(fd); continue; }
                if (e & EPOLLIN)  on_readable(fd);
                if (e & EPOLLOUT) on_writable(fd);
            }
        }
    }
}

void StreamServer::do_accept() {
    for (;;) {
        int cfd = accept4(listen_fd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            break;
        }
        int one = 1;
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        Client c;
        c.fd = cfd;
        clients_.emplace(cfd, std::move(c));

        epoll_event ev{};
        ev.events = EPOLLIN;
        ev.data.fd = cfd;
        epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, cfd, &ev);
    }
}

void StreamServer::on_readable(int fd) {
    auto it = clients_.find(fd);
    if (it == clients_.end()) return;
    Client& c = it->second;

    char buf[4096];
    for (;;) {
        ssize_t r = recv(fd, buf, sizeof(buf), 0);
        if (r > 0) {
            if (!c.streaming) {
                c.reqbuf.append(buf, r);
                if (c.reqbuf.size() > 16384) { close_client(fd); return; }
                if (c.reqbuf.find("\r\n\r\n") != std::string::npos) {
                    handle_request(c);
                    return;
                }
            }
            // Streaming clients shouldn't send; ignore any payload.
        } else if (r == 0) {
            close_client(fd);
            return;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            close_client(fd);
            return;
        }
    }
}

void StreamServer::handle_request(Client& c) {
    // Parse the request line: "GET /path HTTP/1.1".
    std::string line = c.reqbuf.substr(0, c.reqbuf.find("\r\n"));
    std::string method, path;
    {
        std::istringstream iss(line);
        iss >> method >> path;
    }

    if (method != "GET") {
        c.outbuf += "HTTP/1.1 405 Method Not Allowed\r\n"
                    "Access-Control-Allow-Origin: *\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n";
        c.want_close = true;
        update_interest(c);
        return;
    }

    // Strip query string.
    auto q = path.find('?');
    if (q != std::string::npos) path = path.substr(0, q);

    if (path == "/live" || path == "/live/") {
        c.streaming = true;
        client_count_.fetch_add(1);
        c.outbuf +=
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: keep-alive\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "X-Accel-Buffering: no\r\n"
            "\r\n"
            "retry: 2000\n"
            ": connected\n\n";
        update_interest(c);
        return;
    }

    if (path == "/healthz") {
        std::string body = "{\"ok\":true,\"clients\":" +
                           std::to_string(client_count_.load()) + "}";
        c.outbuf += "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    "Access-Control-Allow-Origin: *\r\nContent-Length: " +
                    std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
        c.want_close = true;
        update_interest(c);
        return;
    }

    c.outbuf += "HTTP/1.1 404 Not Found\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Content-Length: 0\r\nConnection: close\r\n\r\n";
    c.want_close = true;
    update_interest(c);
}

void StreamServer::on_writable(int fd) {
    auto it = clients_.find(fd);
    if (it == clients_.end()) return;
    if (!flush(it->second)) close_client(fd);
}

// Returns false if the client should be removed (socket error, or fully
// drained and marked want_close). Never mutates clients_ itself so it is safe
// to call while iterating the client map.
bool StreamServer::flush(Client& c) {
    while (!c.outbuf.empty()) {
        ssize_t w = send(c.fd, c.outbuf.data(), c.outbuf.size(), MSG_NOSIGNAL);
        if (w > 0) {
            c.outbuf.erase(0, (size_t)w);
        } else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        } else if (w < 0 && errno == EINTR) {
            continue;
        } else {
            return false;   // hard error -> drop
        }
    }
    if (c.outbuf.empty() && c.want_close) return false;
    update_interest(c);
    return true;
}

void StreamServer::update_interest(Client& c) {
    bool need_out = !c.outbuf.empty();
    if (need_out == c.epollout) return;
    c.epollout = need_out;
    epoll_event ev{};
    ev.events = EPOLLIN | (need_out ? EPOLLOUT : 0);
    ev.data.fd = c.fd;
    epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, c.fd, &ev);
}

void StreamServer::close_client(int fd) {
    auto it = clients_.find(fd);
    if (it == clients_.end()) return;
    if (it->second.streaming) client_count_.fetch_sub(1);
    epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
    close(fd);
    clients_.erase(it);
}

void StreamServer::drain_queue() {
    std::deque<std::string> local;
    {
        std::lock_guard<std::mutex> lk(qmtx_);
        local.swap(queue_);
    }
    if (local.empty()) return;

    // Append each framed message to every streaming client, then flush.
    // Collect fds to drop and remove them after the loop (flush() never
    // mutates clients_, so iterating is safe).
    std::vector<int> drop;
    for (auto& [fd, c] : clients_) {
        if (!c.streaming) continue;
        for (const auto& msg : local) c.outbuf += msg;
        if (c.outbuf.size() > kMaxClientBuf) { drop.push_back(fd); continue; }
        if (!flush(c)) drop.push_back(fd);
    }
    for (int fd : drop) close_client(fd);
}

} // namespace netmon
