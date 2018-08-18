#ifndef HexDump_h
#define HexDump_h

#include <iomanip>
#include <iostream>

class HexDumpCharHelper {
    const unsigned char *p;
    size_t s;
public:
    HexDumpCharHelper(const unsigned char *pi, size_t si) : p(pi), s(si) {};
    
    inline unsigned char at(size_t n) const {
        if (n >= s) throw std::overflow_error("Invalid offset");
        return p[n];
    }
    
    inline size_t size() const {
        return s;
    }
};

template <typename T>
class HexDump {
protected:
    const T &ptr;
    char delim;
    size_t wrap;
public:
    HexDump(const T &p) : ptr(p), delim(' '), wrap(0) {};
    HexDump(const T &p, size_t w) : ptr(p), delim(' '), wrap(w) {};
    HexDump(const T &p, char d, size_t w) : ptr(p), delim(d), wrap(w) {};
    
    friend std::ostream &operator<<(std::ostream &os, const HexDump &buf)
    {
        size_t i;
        size_t wrap_chars = buf.wrap / 3; // Each printed element is 3 chars wide.
        auto original_os_flags = os.flags();
        os << std::hex << std::setfill('0') << std::right;
        for (i = 0; i < buf.ptr.size(); i++) {
            os << std::setw(2) << static_cast<unsigned int>(buf.ptr.at(i));
            if (i != buf.ptr.size() - 1) os << buf.delim;
            if (buf.wrap && i && !((i + 1) % wrap_chars)) os << "\n";
        }
        if (buf.wrap && ((i + 1) % wrap_chars)) os << "\n";
        os.flags(original_os_flags);
        return os;
    }
};

#endif /* HexDump_h */
