#ifndef StackTracePrinter_h
#define StackTracePrinter_h

#include <iostream>
#include <memory>
#include <stdexcept>
#include <exception>
#include <array>

#include <cxxabi.h>
#include <execinfo.h>

template <size_t STACK_ELEMENTS>
class StackTracePrinter {
public:
    inline void operator()() const {
        std::array<void *, STACK_ELEMENTS> elems;
        int count = backtrace(elems.data(), elems.size());
        char **symbols = backtrace_symbols(elems.data(), elems.size());
        std::exception_ptr ep = std::current_exception();

        if (ep) {
            try {
                std::rethrow_exception(ep); // Have to re-throw to make it usable.
            } catch (const std::exception &e) {
                std::clog << "Caught unhandled exception: " << e.what() << "\n";
            } catch (...) {
                std::clog << "Caught unhandled and unknown exception\n";
            }
        } else {
            std::clog << "Caught unhandled and unknown exception\n";
        }

        if (!symbols) {
            std::clog << "Failed to get backtrace\n";
            return;
        }
        
        for (int i = 0; i < count; i++) {
            /*
             0   shades                              0x00000001000059dc _Z12on_terminatev + 28
             1   libc++abi.dylib                     0x00007fff5dac97c9 _ZSt11__terminatePFvvE + 8
             2   libc++abi.dylib                     0x00007fff5dac926f _ZN10__cxxabiv1L22exception_cleanup_funcE19_Unwind_Reason_CodeP17_Unwind_Exception + 0
             3   shades                              0x0000000100022a3d _ZN14IPv4SubnetMask6assignENSt3__117basic_string_viewIcNS0_11char_traitsIcEEEE + 205
             4   shades                              0x0000000100006ca5 _ZN14IPv4SubnetMaskaSENSt3__117basic_string_viewIcNS0_11char_traitsIcEEEE + 53
             5   shades                              0x00000001000065ca main + 1466
             6   libdyld.dylib                       0x00007fff5fb06015 start + 1
             */
            
            const std::string &row = symbols[i];
            const int LOOKING_FOR_FIELD = 3;
            int found_fields = 0;
            bool in_delim = false;
            for(size_t i1 = 0; i1 < row.size(); i1++) {
                char c = row[i1];
                std::clog << c;
                if (c == ' ' && !in_delim) in_delim = true;
                else if (c != ' ' && in_delim) {
                    in_delim = false;
                    found_fields++;
                    if (found_fields == LOOKING_FOR_FIELD) {
                        size_t i2;
                        for(i2 = i1; i2 < row.size(); i2++) if (row[i2] == ' ') break;
                        std::string mangled_name = row.substr(i1, i2 - i1);
                        pretty_mangled_name(mangled_name);
                        i1 = i2 - 1;
                        continue;
                    }
                }
            }
            std::clog << '\n';
        }
        free(symbols);
    }

    inline void pretty_mangled_name(const std::string &sv) const {
        int status;
        if (char *dm = abi::__cxa_demangle(sv.data(), 0, 0, &status)) {
            std::clog << dm;
            free(dm);
        } else {
            std::clog << sv;
        }
    }
};

#endif /* StackTracePrinter_h */
