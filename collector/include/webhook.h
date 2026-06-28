// SPDX-License-Identifier: GPL-2.0
#pragma once
#include <string>
#include <deque>
#include <utility>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <atomic>

namespace netmon {

// Fire-and-forget HTTP POST sender for high-severity security events, delivered
// to the client's own endpoint (e.g. https://<domain>/api/webhook). A single
// background thread drains a bounded queue, so a slow or unreachable endpoint
// never blocks the scrape loop and never grows memory without bound (oldest
// queued events are dropped past the cap). Everything is still written to
// ClickHouse regardless — this is only the "tell me now" channel.
class WebhookSender {
public:
    WebhookSender(std::string url, std::string token, bool verbose);
    ~WebhookSender();

    // Queue one JSON event object for delivery (non-blocking).
    void enqueue(const std::string& json_body, const std::string& category);

private:
    void run();

    std::string url_, token_;
    bool        verbose_;
    std::deque<std::pair<std::string, std::string>> q_;   // (body, category)
    std::mutex  mtx_;
    std::condition_variable cv_;
    std::atomic<bool> stop_{false};
    std::thread thr_;
    static constexpr size_t kMaxQueue = 1000;
};

} // namespace netmon
