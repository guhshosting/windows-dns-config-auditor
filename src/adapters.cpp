#include "acquisition.h"
#include <iphlpapi.h>
#include <memory>
namespace audit {
namespace {
std::string state(IF_OPER_STATUS value) {
    switch (value) {
    case IfOperStatusUp:
        return "up";
    case IfOperStatusDown:
        return "down";
    case IfOperStatusTesting:
        return "testing";
    case IfOperStatusUnknown:
        return "unknown";
    case IfOperStatusDormant:
        return "dormant";
    case IfOperStatusNotPresent:
        return "not_present";
    case IfOperStatusLowerLayerDown:
        return "lower_layer_down";
    default:
        return "unexpected";
    }
}
} // namespace
void acquire_adapters(Result &r) {
    ULONG bytes = 16384;
    ULONG status = ERROR_BUFFER_OVERFLOW;
    std::unique_ptr<unsigned char[]> buffer;
    for (int attempt = 0; attempt < 5 && status == ERROR_BUFFER_OVERFLOW; ++attempt) {
        if (bytes > 16 * 1024 * 1024)
            throw ApiError("Adapter configuration exceeds safety bound");
        buffer = std::make_unique<unsigned char[]>(bytes);
        status = GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                GAA_FLAG_INCLUDE_ALL_INTERFACES,
            nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.get()), &bytes);
    }
    if (status == ERROR_NO_DATA) {
        r.warnings.push_back("No adapter configuration returned.");
    } else if (status != NO_ERROR)
        throw ApiError("GetAdaptersAddresses failed: " + std::to_string(status));
    else {
        for (auto *p = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.get()); p; p = p->Next) {
            Adapter a;
            a.id = p->AdapterName ? p->AdapterName : "";
            a.name = utf8(p->FriendlyName ? p->FriendlyName : L"");
            a.description = utf8(p->Description ? p->Description : L"");
            a.index = p->IfIndex;
            a.index6 = p->Ipv6IfIndex;
            a.luid = p->Luid.Value;
            a.type = p->IfType;
            a.status = state(p->OperStatus);
            a.active = p->OperStatus == IfOperStatusUp;
            a.ipv4 = (p->Flags & IP_ADAPTER_IPV4_ENABLED) != 0;
            a.ipv6 = (p->Flags & IP_ADAPTER_IPV6_ENABLED) != 0;
            acquire_registration(a, p->Flags);
            a.suffix = utf8(p->DnsSuffix ? p->DnsSuffix : L"");
            acquire_servers(a, p->FirstDnsServerAddress);
            r.adapters.push_back(std::move(a));
        }
    }
}
} // namespace audit
