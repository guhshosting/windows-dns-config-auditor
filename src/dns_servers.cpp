#include "acquisition.h"
namespace audit {
void acquire_servers(Adapter &adapter, const IP_ADAPTER_DNS_SERVER_ADDRESS *list) {
    for (auto *server = list; server; server = server->Next)
        adapter.servers.push_back(
            format_address(server->Address.lpSockaddr, server->Address.iSockaddrLength));
}
} // namespace audit
