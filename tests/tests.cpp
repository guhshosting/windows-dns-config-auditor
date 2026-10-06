#include "model.h"
#include <algorithm>
#include <iostream>
#include <winsock2.h>
#include <ws2ipdef.h>
namespace {
void check(bool b) {
    if (!b)
        throw std::runtime_error("Test failed");
}
} // namespace
int main(int argc, char **argv) {
    try {
        sockaddr_in a{};
        a.sin_family = AF_INET;
        auto *b = reinterpret_cast<unsigned char *>(&a.sin_addr);
        b[0] = 127;
        b[3] = 1;
        auto s = audit::format_address(&a, sizeof(a));
        check(s.address == "127.0.0.1" && s.loopback && s.family == "IPv4");
        b[0] = 8;
        b[1] = 8;
        b[2] = 4;
        b[3] = 4;
        auto v4 = audit::format_address(&a, sizeof(a));
        check(v4.address == "8.8.4.4" && !v4.loopback);
        sockaddr_in6 a6{};
        a6.sin6_family = AF_INET6;
        auto *c = reinterpret_cast<unsigned char *>(&a6.sin6_addr);
        c[0] = 0xfe;
        c[1] = 0x80;
        c[15] = 1;
        a6.sin6_scope_id = 7;
        auto v6 = audit::format_address(&a6, sizeof(a6));
        check(v6.link_local && v6.scope == 7 && v6.address == "fe80:0:0:0:0:0:0:1%7");
        check(!audit::format_address(nullptr, 0).valid);
        check(!audit::format_address(&a, 1).valid);
        a.sin_family = 999;
        check(!audit::format_address(&a, sizeof(a)).valid);
        c[0] = 0;
        c[1] = 0;
        a6.sin6_scope_id = 0;
        check(audit::format_address(&a6, sizeof(a6)).loopback);
        c[15] = 0;
        check(audit::format_address(&a6, sizeof(a6)).unspecified);
        audit::Result r;
        audit::Adapter ad;
        ad.id = "fixture";
        ad.name = audit::utf8(L"網路 café 🚀");
        ad.active = true;
        ad.ipv4 = true;
        ad.ipv6 = true;
        ad.suffix = "example.test";
        ad.servers = {v4, v6, s, v4};
        r.adapters.push_back(ad);
        ad.id = "empty";
        ad.servers.clear();
        r.adapters.push_back(ad);
        ad.id = "inactive";
        ad.active = false;
        r.adapters.push_back(ad);
        audit::analyze(r);
        auto has = [&](const char *code, const char *id) {
            return std::any_of(r.findings.begin(), r.findings.end(),
                               [&](const auto &f) { return f.code == code && f.adapter == id; });
        };
        check(has("duplicate_server", "fixture"));
        check(has("loopback_resolver", "fixture"));
        check(has("link_local_resolver", "fixture"));
        check(has("no_dns_servers", "empty"));
        check(!has("no_dns_servers", "inactive"));
        check(has("different_active_configurations", ""));
        check(has("suffix_configured", "fixture"));
        r.hostname = "quote\"\\\n\t";
        r.search_lists.push_back({"fixture", "available", "a.test,b.test"});
        auto j = audit::json(r);
        check(j.find("quote\\\"\\\\\\n\\t") != std::string::npos);
        check(j.find(ad.name) != std::string::npos);
        check(j.find("raw_value") != std::string::npos);
        check(audit::human(r, true).find("inactive") != std::string::npos);
        check(audit::parse({L"--all", L"--json"}).json);
        check(audit::parse({L"--help"}).help);
        check(audit::parse({L"--version"}).version);
        for (const auto &args : std::vector<std::vector<std::wstring>>{
                 {L"bad"}, {L"--all", L"--all"}, {L"--help", L"--json"}}) {
            bool failed = false;
            try {
                audit::parse(args);
            } catch (const std::invalid_argument &) {
                failed = true;
            }
            check(failed);
        }
        if (argc == 2 && std::string(argv[1]) == "--emit-json")
            std::cout << audit::json(r);
        else
            std::cout << "Synthetic address, analysis, Unicode, formatting and CLI tests passed\n";
        return 0;
    } catch (const std::exception &e) {
        static_cast<void>(e);
        return 1;
    } catch (...) {
        return 1;
    }
}
