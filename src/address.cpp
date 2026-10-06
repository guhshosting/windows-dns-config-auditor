#include "model.h"
#include <cstring>
#include <sstream>
#include <winsock2.h>
#include <ws2ipdef.h>
namespace audit {
Server format_address(const void *ptr, int length) {
    Server s;
    s.family = "unknown";
    if (!ptr || length < static_cast<int>(sizeof(ADDRESS_FAMILY)))
        return s;
    ADDRESS_FAMILY family = 0;
    std::memcpy(&family, ptr, sizeof(family));
    if (family == AF_INET && length >= static_cast<int>(sizeof(sockaddr_in))) {
        sockaddr_in a{};
        std::memcpy(&a, ptr, sizeof(a));
        const auto *b = reinterpret_cast<const unsigned char *>(&a.sin_addr);
        s.family = "IPv4";
        s.address = std::to_string(b[0]) + "." + std::to_string(b[1]) + "." + std::to_string(b[2]) +
                    "." + std::to_string(b[3]);
        s.loopback = b[0] == 127;
        s.link_local = b[0] == 169 && b[1] == 254;
        s.unspecified = b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0;
        s.multicast = b[0] >= 224;
        s.valid = true;
    } else if (family == AF_INET6 && length >= static_cast<int>(sizeof(sockaddr_in6))) {
        sockaddr_in6 a{};
        std::memcpy(&a, ptr, sizeof(a));
        const auto *b = reinterpret_cast<const unsigned char *>(&a.sin6_addr);
        std::ostringstream out;
        out << std::hex;
        bool zero = true;
        for (int i = 0; i < 16; ++i)
            zero = zero && b[i] == 0;
        bool first_zero = true;
        for (int i = 0; i < 15; ++i)
            first_zero = first_zero && b[i] == 0;
        for (int i = 0; i < 16; i += 2) {
            if (i)
                out << ":";
            out << ((static_cast<unsigned>(b[i]) << 8U) | static_cast<unsigned>(b[i + 1]));
        }
        s.scope = a.sin6_scope_id;
        s.address = out.str();
        if (s.scope)
            s.address += "%" + std::to_string(s.scope);
        s.family = "IPv6";
        s.valid = true;
        s.unspecified = zero;
        s.loopback = first_zero && b[15] == 1;
        s.link_local = b[0] == 0xfe && (static_cast<unsigned>(b[1]) & 0xc0U) == 0x80U;
        s.multicast = b[0] == 0xff;
    }
    return s;
}
} // namespace audit
