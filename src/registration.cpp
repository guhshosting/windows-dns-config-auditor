#include "acquisition.h"
namespace audit {
void acquire_registration(Adapter &adapter, ULONG flags) {
    adapter.registration = (flags & IP_ADAPTER_DDNS_ENABLED) != 0;
    adapter.suffix_registration = (flags & IP_ADAPTER_REGISTER_ADAPTER_SUFFIX) != 0;
}
} // namespace audit
