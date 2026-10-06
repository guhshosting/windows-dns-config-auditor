#pragma once
#include "model.h"
#include <winsock2.h>
#include <windows.h>
#include <iptypes.h>
namespace audit {
void acquire_suffixes(Result &result);
void acquire_adapters(Result &result);
void acquire_servers(Adapter &adapter, const IP_ADAPTER_DNS_SERVER_ADDRESS *list);
void acquire_registration(Adapter &adapter, ULONG flags);
} // namespace audit
