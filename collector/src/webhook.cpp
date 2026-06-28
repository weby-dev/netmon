// SPDX-License-Identifier: GPL-2.0
#include "webhook.h"
#include <curl/curl.h>
#include <cstdio>

namespace netmon {

namespace {
size_t discard(char*, size_t size, size_t nmemb, void*) { return size * nmemb; }
} // namespace

WebhookSender::WebhookSender(std::string url, std::string token, bool verbose)
    : url_(std::move(url)), token_(std::move(token)), verbose_(verbose) {
    // curl_global_init() is performed by ClickHouseClient on the main thread
    // before this thread starts; here we only use per-handle curl_easy_*.
    thr_ = std::thread(&WebhookSender::run, this);
}

WebhookSender::~WebhookSender() {
    { std::lock_guard<std::mutex> lk(mtx_); stop_ = true; }
    cv_.notify_all();
    if (thr_.joinable()) thr_.join();
}

void WebhookSender::enqueue(const std::string& body, const std::string& category) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (q_.size() >= kMaxQueue) q_.pop_front();   // drop oldest, never block
    q_.emplace_back(body, category);
    cv_.notify_one();
}

void WebhookSender::run() {
    while (true) {
        std::pair<std::string, std::string> item;
        {
            std::unique_lock<std::mutex> lk(mtx_);
            cv_.wait(lk, [&] { return stop_.load() || !q_.empty(); });
            if (stop_.load()) return;          // shut down promptly (queued events stay in DB)
            item = std::move(q_.front());
            q_.pop_front();
        }

        CURL* curl = curl_easy_init();
        if (!curl) continue;
        struct curl_slist* hdrs = nullptr;
        hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
        hdrs = curl_slist_append(hdrs, ("X-Netmon-Event: " + item.second).c_str());
        if (!token_.empty())
            hdrs = curl_slist_append(hdrs, ("X-Netmon-Token: " + token_).c_str());

        curl_easy_setopt(curl, CURLOPT_URL, url_.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, item.first.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)item.first.size());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 8L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);   // thread-safe timeouts
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

        CURLcode rc = curl_easy_perform(curl);
        long http = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http);
        if (verbose_ && (rc != CURLE_OK || http >= 400)) {
            std::fprintf(stderr, "[webhook] %s -> %ld %s\n", item.second.c_str(), http,
                         rc == CURLE_OK ? "" : curl_easy_strerror(rc));
        }
        curl_slist_free_all(hdrs);
        curl_easy_cleanup(curl);
    }
}

} // namespace netmon
