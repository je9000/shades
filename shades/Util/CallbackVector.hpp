#ifndef CallbackVector_h
#define CallbackVector_h

#include <functional>
#include <vector>
#include <random>

template <typename T>
class CallbackInfo {
public:
    T func;
    void *data;
    size_t id;
    CallbackInfo(T f, void *d, size_t cid) : func(f), data(d), id(cid) {}
};

template <typename T, typename... Ts>
class CallbackVector {
private:
    std::minstd_rand rand_numbers;
    
    size_t get_next_id() {
        bool keep_looking = true;
        size_t id = rand_numbers();

        while(keep_looking) {
            keep_looking = false;
            for (const auto &cb : callbacks) {
                if (cb.id == id) {
                    id++;
                    keep_looking = true;
                    break;
                }
            }
        }

        return id;
    }
public:
    CallbackVector() {
        std::random_device rd;
        rand_numbers.seed(rd());
    }

    void remove(const size_t id) {
        for(auto it = callbacks.begin(); it != callbacks.end(); ++it) {
            if (it->id == id) {
                callbacks.erase(it);
                return;
            }
        }
    }

    size_t add(const T &callback, void *data = nullptr) {
        size_t id = get_next_id();
        callbacks.push_back({callback, data, id});
        return id;
    }
    
    void call_all(Ts ...args) const {
        for (auto &cb : callbacks) {
            cb.func(cb.id, cb.data, args...);
        }
    }
    
    void call_until_false(Ts ...args) const {
        for (auto &cb : callbacks) {
            if (!cb.func(cb.id, cb.data, args...)) break;
        }
    }

    std::vector<CallbackInfo<T>> callbacks;
};

#endif /* CallbackVector_h */
