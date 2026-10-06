#include "model.h"
#include <iomanip>
#include <sstream>
namespace audit {
namespace {
std::string quote(const std::string &s) {
    std::ostringstream o;
    o << '"';
    for (unsigned char c : s) {
        switch (c) {
        case '"':
            o << "\\\"";
            break;
        case '\\':
            o << "\\\\";
            break;
        case '\n':
            o << "\\n";
            break;
        case '\r':
            o << "\\r";
            break;
        case '\t':
            o << "\\t";
            break;
        default:
            if (c < 32)
                o << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                  << static_cast<unsigned>(c) << std::dec;
            else
                o << static_cast<char>(c);
        }
    }
    o << '"';
    return o.str();
}
const char *boolean(bool b) { return b ? "true" : "false"; }
void strings(std::ostringstream &o, const std::vector<std::string> &values) {
    o << '[';
    bool first = true;
    for (const auto &v : values) {
        if (!first)
            o << ',';
        first = false;
        o << quote(v);
    }
    o << ']';
}
std::string visible(const std::string &s) {
    std::string out;
    for (unsigned char c : s) {
        if (c < 32 || c == 127) {
            out += '?';
        } else
            out += static_cast<char>(c);
    }
    return out;
}
} // namespace
std::string json(const Result &r) {
    std::ostringstream o;
    o << "{\"schema_version\":\"1.0\",\"application_version\":\"1.0.0\",\"system\":{\"hostname\":"
      << quote(r.hostname) << ",\"primary_dns_suffix\":" << quote(r.primary_suffix)
      << ",\"source\":\"GetComputerNameExW (physical DNS "
         "name)\"},\"suffix_configuration\":{\"search_lists\":[";
    bool first = true;
    for (const auto &s : r.search_lists) {
        if (!first)
            o << ',';
        first = false;
        o << "{\"source\":" << quote(s.source) << ",\"status\":" << quote(s.status)
          << ",\"raw_value\":" << quote(s.value) << '}';
    }
    o << "]},\"adapters\":[";
    first = true;
    for (const auto &a : r.adapters) {
        if (!first)
            o << ',';
        first = false;
        o << "{\"id\":" << quote(a.id) << ",\"friendly_name\":" << quote(a.name)
          << ",\"description\":" << quote(a.description) << ",\"interface_index\":" << a.index
          << ",\"ipv6_interface_index\":" << a.index6
          << ",\"luid\":" << quote(std::to_string(a.luid)) << ",\"interface_type\":" << a.type
          << ",\"operational_status\":" << quote(a.status) << ",\"active\":" << boolean(a.active)
          << ",\"ipv4_enabled\":" << boolean(a.ipv4) << ",\"ipv6_enabled\":" << boolean(a.ipv6)
          << ",\"connection_suffix\":" << quote(a.suffix)
          << ",\"registration_enabled\":" << boolean(a.registration)
          << ",\"suffix_registration_enabled\":" << boolean(a.suffix_registration)
          << ",\"source\":\"GetAdaptersAddresses\",\"dns_servers\":[";
        bool fs = true;
        for (const auto &s : a.servers) {
            if (!fs)
                o << ',';
            fs = false;
            o << "{\"address\":" << quote(s.address) << ",\"family\":" << quote(s.family)
              << ",\"scope_id\":" << s.scope << ",\"valid\":" << boolean(s.valid)
              << ",\"loopback\":" << boolean(s.loopback)
              << ",\"link_local\":" << boolean(s.link_local)
              << ",\"unspecified\":" << boolean(s.unspecified)
              << ",\"multicast_or_reserved\":" << boolean(s.multicast) << '}';
        }
        o << "]}";
    }
    o << "],\"findings\":[";
    first = true;
    for (const auto &f : r.findings) {
        if (!first)
            o << ',';
        first = false;
        o << "{\"code\":" << quote(f.code) << ",\"adapter_id\":" << quote(f.adapter)
          << ",\"message\":" << quote(f.message) << '}';
    }
    o << "],\"warnings\":";
    strings(o, r.warnings);
    o << ",\"limitations\":";
    strings(o, r.limitations);
    o << "}\n";
    return o.str();
}
std::string human(const Result &r, bool all) {
    std::ostringstream o;
    o << "windows-dns-config-auditor 1.0.0\n\nSystem DNS summary\n  Host: " << visible(r.hostname)
      << "\n  Primary DNS suffix: "
      << (r.primary_suffix.empty() ? "(empty or unavailable)" : visible(r.primary_suffix))
      << "\n  Source: GetComputerNameExW (physical DNS name)\n\nActive interfaces (operationally "
         "up)\n";
    size_t inactive = 0;
    for (const auto &a : r.adapters) {
        if (!a.active) {
            ++inactive;
            continue;
        }
        o << "  " << visible(a.name) << " [" << visible(a.id) << "] index " << a.index
          << " IPv6 index " << a.index6 << " type " << a.type << " LUID " << a.luid << "\n    "
          << visible(a.description) << "; IPv4 " << boolean(a.ipv4) << ", IPv6 " << boolean(a.ipv6)
          << "\n";
    }
    o << "  Inactive interfaces: " << inactive
      << " (use --all for details)\n\nConfigured DNS servers (GetAdaptersAddresses list order)\n";
    for (const auto &a : r.adapters) {
        if (!all && !a.active)
            continue;
        o << "  " << visible(a.name) << " (" << a.status << ")\n";
        if (a.servers.empty())
            o << "    (none reported)\n";
        for (const auto &s : a.servers)
            o << "    " << s.family << " "
              << (s.valid ? s.address : "(malformed or unsupported address)") << "\n";
    }
    o << "\nSuffix/registration configuration\n";
    for (const auto &s : r.search_lists)
        o << "  " << s.source << ": " << s.status << "; raw value: " << visible(s.value) << "\n";
    for (const auto &a : r.adapters) {
        if (!all && !a.active)
            continue;
        o << "  " << visible(a.name) << ": suffix "
          << (a.suffix.empty() ? "(empty)" : visible(a.suffix)) << "; registration "
          << boolean(a.registration) << "; register connection suffix "
          << boolean(a.suffix_registration) << " [GetAdaptersAddresses]\n";
    }
    o << "\nFindings\n";
    if (r.findings.empty())
        o << "  None.\n";
    for (const auto &f : r.findings)
        o << "  [" << f.code << "] " << visible(f.adapter) << " " << f.message << "\n";
    for (const auto &w : r.warnings)
        o << "  Warning: " << w << "\n";
    o << "\nLimitations\n";
    for (const auto &l : r.limitations)
        o << "  " << l << "\n";
    return o.str();
}
} // namespace audit
