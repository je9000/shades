#ifndef NetworkingInput_h
#define NetworkingInput_h

#include <typeinfo>
#include <typeindex>
#include <unordered_map>
#include <vector>
#include <functional>
#include <chrono>

#include "PacketHeaders.hpp"
#include "NetDriver.hpp"

class NetworkingInput;
typedef std::function<bool(NetworkingInput &, PacketHeader &, void *)> NetworkingInputCallback;
class NetworkingInputCallbackInfo {
public:
    NetworkingInputCallback func;
    void *data;
    NetworkingInputCallbackInfo(NetworkingInputCallback f, void *d) : func(f), data(d) {}
};

using NetworkingInputSteadyClock = std::chrono::steady_clock;
using NetworkingInputSteadyClockTime = std::chrono::time_point<NetworkingInputSteadyClock>;
typedef std::function<void(NetworkingInput &, NetworkingInputSteadyClockTime, void *)> NetworkingTimerCallback;
class NetworkingTimerCallbackInfo {
public:
    NetworkingTimerCallback func;
    void *data;
    NetworkingTimerCallbackInfo(NetworkingTimerCallback f, void *d) : func(f), data(d) {}
};

class NetworkingInput {
private:
    NetDriver &net_driver;
    
    std::unordered_map<std::type_index, std::vector<const NetworkingInputCallbackInfo>> packet_type_callbacks;
    std::vector<const NetworkingTimerCallbackInfo> timer_callbacks;
public:
    bool keep_running;

    NetworkingInput(NetDriver &nd) : net_driver(nd), keep_running(false) {}
    
    void register_callback(const std::type_info &, const NetworkingInputCallback &, void *data = nullptr);
    void register_timer_callback(const NetworkingTimerCallback &, void *data = nullptr);
    
    void run();

    void process_one(PacketBuffer &);
    
    bool process_ethernet(PacketBufferOffset);
    bool process_ipv4(PacketBufferOffset);
};

#endif /* NetworkingInput_h */
