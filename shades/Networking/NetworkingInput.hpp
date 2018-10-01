#ifndef NetworkingInput_h
#define NetworkingInput_h

#include <typeinfo>
#include <typeindex>
#include <unordered_map>
#include <vector>
#include <functional>
#include <chrono>

#include "CallbackVector.hpp"
#include "PacketHeaders.hpp"
#include "NetDriver.hpp"

static const std::chrono::seconds NETWORKING_INPUT_TIMER_INTERVAL(1);

class NetworkingInput;
typedef std::function<bool(size_t, void *, NetworkingInput &, PacketHeader &)> NetworkingInputCallback;

using NetworkingInputSteadyClock = std::chrono::steady_clock;
using NetworkingInputSteadyClockTime = std::chrono::time_point<NetworkingInputSteadyClock>;
typedef std::function<void(size_t, void *, NetworkingInput &, NetworkingInputSteadyClockTime)> NetworkingTimerCallback;

class NetworkingInput {
private:
    NetDriver &net_driver;
    NetworkingInputSteadyClockTime last_packet_time;
    
    std::unordered_map<std::type_index, CallbackVector<NetworkingInputCallback, NetworkingInput &, PacketHeader &>> packet_type_callbacks;
    CallbackVector<NetworkingTimerCallback, NetworkingInput &, NetworkingInputSteadyClockTime> timer_callbacks;
public:
    bool keep_running;

    NetworkingInput(NetDriver &nd) : net_driver(nd), last_packet_time(NetworkingInputSteadyClock::now()), keep_running(false) {}

    size_t register_callback(const std::type_info &, const NetworkingInputCallback &, void *data = nullptr);
    void unregister_callback(const std::type_info &, const size_t);
    size_t register_timer_callback(const NetworkingTimerCallback &, void *data = nullptr);
    void unregister_timer_callback(const size_t);

    NetDriver &get_driver();
    void run();
    void check_timers();
    void process_one(PacketBuffer &);

    bool process_ethernet(PacketBufferOffset);
    bool process_ipv4(PacketBufferOffset);
};

#endif /* NetworkingInput_h */
