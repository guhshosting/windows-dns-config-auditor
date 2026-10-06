#include "model.h"
#include <set>
namespace audit {
void analyze(Result &r) {
    r.findings.clear();
    std::set<std::vector<std::string>> active_configs;
    for (const auto &a : r.adapters) {
        auto add = [&](const char *code, const char *message) {
            r.findings.push_back({code, a.id, message});
        };
        if (a.active && a.servers.empty() && (a.ipv4 || a.ipv6))
            add("no_dns_servers", "Operationally up IP interface has no DNS servers reported.");
        std::set<std::string> seen;
        std::vector<std::string> config;
        for (const auto &s : a.servers) {
            config.push_back(s.family + ":" + s.address);
            if (!seen.insert(s.family + ":" + s.address).second)
                add("duplicate_server", "Duplicate DNS server entry in API list.");
            if (!s.valid || s.unspecified || s.multicast)
                add("unusual_server",
                    "Invalid, unspecified, multicast or reserved-looking server address reported.");
            if (s.loopback)
                add("loopback_resolver",
                    "Loopback DNS resolver configured; no availability test performed.");
            if (s.link_local)
                add("link_local_resolver", "Link-local DNS resolver configured.");
            if (s.family == "IPv6" && s.link_local && !s.scope)
                add("missing_scope", "Link-local IPv6 server has no scope identifier reported.");
        }
        if (a.active && (a.ipv4 || a.ipv6))
            active_configs.insert(config);
        if (!a.suffix.empty())
            add("suffix_configured", "Connection-specific DNS suffix is configured.");
        if (!a.registration)
            add("registration_disabled", "Adapter dynamic DNS registration flag is disabled.");
    }
    if (active_configs.size() > 1)
        r.findings.push_back({"different_active_configurations", "",
                              "Operationally up IP interfaces expose different ordered DNS server "
                              "lists; resolver selection is not predicted."});
}
} // namespace audit
