#pragma once
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>
namespace audit {
struct Server {
    std::string address, family;
    bool valid = false, loopback = false, link_local = false, unspecified = false,
         multicast = false;
    std::uint32_t scope = 0;
};
struct Adapter {
    std::string id, name, description, status;
    std::uint32_t index = 0, index6 = 0, type = 0;
    std::uint64_t luid = 0;
    bool active = false, ipv4 = false, ipv6 = false, registration = false,
         suffix_registration = false;
    std::string suffix;
    std::vector<Server> servers;
};
struct Setting {
    std::string source, status, value;
};
struct Finding {
    std::string code, adapter, message;
};
struct Result {
    std::string hostname, primary_suffix;
    std::vector<Setting> search_lists;
    std::vector<Adapter> adapters;
    std::vector<Finding> findings;
    std::vector<std::string> warnings, limitations;
};
struct Options {
    bool all = false, json = false, help = false, version = false;
};
struct ApiError : std::runtime_error {
    using std::runtime_error::runtime_error;
};
std::string utf8(const std::wstring &value);
Server format_address(const void *address, int length);
Options parse(const std::vector<std::wstring> &args);
Result acquire();
void analyze(Result &result);
std::string json(const Result &result);
std::string human(const Result &result, bool all);
} // namespace audit
