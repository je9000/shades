#ifndef PacketQueue_h
#define PacketQueue_h

#include <array>
#include <list>
#include <mutex>
#include <functional>
#include <exception>

#include "PacketBuffer.hpp"

#define PACKET_QUEUE_SANITY_CHECK

typedef std::function<bool(PacketBuffer *, void *, bool &)> ReadablePacketCallback;

template <size_t N>
class PacketQueue {
private:
    std::array<PacketBuffer, N> buf;
    std::list<PacketBuffer *> readable; // These two should be some custom class that's like a ring buffer
    std::list<PacketBuffer *> writable;
    std::timed_mutex read_lock;
    std::timed_mutex write_lock;
public:
    
    PacketQueue() {
        for (PacketBuffer &entry : buf) {
            writable.push_back(&entry);
        }
    }
    
    PacketBuffer *get_writable() {
        {
            std::lock_guard<std::timed_mutex> L(write_lock);
            if (!writable.empty()) {
                auto w = writable.front();
                writable.pop_front();
                return w;
            }
        }
        
        std::lock_guard<std::timed_mutex> L(read_lock);
        if (!readable.empty()) {
            auto r = readable.front();
            readable.pop_front();
            return r;
        }
        return nullptr;
    }
    
    // This probably never gets called. Maybe on a read-abort?
    void put_writable(PacketBuffer *pb) {
#ifdef PACKET_QUEUE_SANITY_CHECK
        {
            std::lock_guard<std::timed_mutex> L(read_lock);
            if (std::find(readable.begin(), readable.end(), pb) != readable.end()) {
                throw std::runtime_error("Element already in readable list");
            }
        }
        std::lock_guard<std::timed_mutex> L(write_lock);
        if (std::find(writable.begin(), writable.end(), pb) != writable.end()) {
            throw std::runtime_error("Element already in writable list");
        }
#else
        std::lock_guard<std::timed_mutex> L(write_lock);
#endif
        writable.push_back(pb);
    }
    
    PacketBuffer *get_readable() {
        std::lock_guard<std::timed_mutex> L(read_lock);
        if (!readable.empty()) {
            auto r = readable.front();
            readable.pop_front();
            return r;
        }
        return nullptr;
    }
    
    void put_readable(PacketBuffer *pb) {
#ifdef PACKET_QUEUE_SANITY_CHECK
        {
            std::lock_guard<std::timed_mutex> L(write_lock);
            if (std::find(writable.begin(), writable.end(), pb) != writable.end()) {
                throw std::runtime_error("Element already in writable list");
            }
        }
        std::lock_guard<std::timed_mutex> L(read_lock);
        if (std::find(readable.begin(), readable.end(), pb) != readable.end()) {
            throw std::runtime_error("Element already in readable list");
        }
#else
        std::lock_guard<std::timed_mutex> L(read_lock);
#endif
        readable.push_back(pb);
    }
    
    void scan_readable(const ReadablePacketCallback &cb, void *arg) {
        std::array<PacketBuffer *, N> newly_writable;
        size_t nw = 0;
        {
            std::lock_guard<std::timed_mutex> L(read_lock);
            for (auto it = readable.begin(); it != readable.end();) {
                bool remove_item = false;
                bool continue_processing = cb(*it, arg, remove_item);
                if (remove_item) {
                    it = readable.erase(it);
                    newly_writable[nw++] = *it;
                } else {
                    ++it;
                }
                if (!continue_processing) break;
            }
        }
        std::lock_guard<std::timed_mutex> L(write_lock);
        for (size_t i = 0; i < nw; i++) {
            writable.push_back(newly_writable[i]);
        }
    }
};

#ifdef TEST_PACKET_QUEUE
#include <cassert>

typedef PacketQueue<10> TestQueue;

static size_t count_num_found(TestQueue &queue) {
    size_t num_found = 0;
    queue.scan_readable(
                        [&num_found](PacketBuffer *pb, void *data, bool &remove) {
                            num_found++;
                            return true;
                        },
                        nullptr);
    return num_found;
}

void TestPacketQueue() {
    TestQueue queue;
    
    assert(queue.get_readable() == nullptr);
    assert(count_num_found(queue) == 0);
    
    auto w = queue.get_writable();
    assert(w);
    queue.put_readable(w);
    auto r = queue.get_readable();
    assert(r);
    assert(count_num_found(queue) == 0);
    queue.put_readable(w);
    assert(count_num_found(queue) == 1);
    queue.scan_readable(
                        [](PacketBuffer *pb, void *data, bool &remove) {
                            remove = true;
                            return true;
                        },
                        nullptr);
    assert(count_num_found(queue) == 0);
}

#endif

#endif /* PacketQueue_h */
