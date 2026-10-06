#include "acquisition.h"
namespace audit {
namespace {
std::string computer(COMPUTER_NAME_FORMAT format, Result &r) {
    DWORD size = 0;
    GetComputerNameExW(format, nullptr, &size);
    if (!size || size > 65536) {
        r.warnings.push_back("Computer DNS name unavailable.");
        return {};
    }
    std::wstring value(size, L'\0');
    if (!GetComputerNameExW(format, value.data(), &size)) {
        r.warnings.push_back("Computer DNS name acquisition failed: " +
                             std::to_string(GetLastError()));
        return {};
    }
    value.resize(size);
    return utf8(value);
}
Setting search(const wchar_t *path, const char *source) {
    Setting s{source, "unavailable", {}};
    DWORD bytes = 0;
    LSTATUS status = RegGetValueW(HKEY_LOCAL_MACHINE, path, L"SearchList",
                                  RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, nullptr, nullptr, &bytes);
    if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) {
        s.status = "absent";
        return s;
    }
    if (status != ERROR_SUCCESS || bytes > 131072 || bytes % sizeof(wchar_t) != 0) {
        s.status = "unavailable (error " + std::to_string(status) + ")";
        return s;
    }
    std::vector<wchar_t> buffer(static_cast<size_t>(bytes) / sizeof(wchar_t) + 1, L'\0');
    status = RegGetValueW(HKEY_LOCAL_MACHINE, path, L"SearchList",
                          RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, nullptr, buffer.data(), &bytes);
    if (status != ERROR_SUCCESS) {
        s.status = "unavailable (error " + std::to_string(status) + ")";
        return s;
    }
    s.status = "available";
    s.value = utf8(buffer.data());
    return s;
}
} // namespace
void acquire_suffixes(Result &r) {
    r.hostname = computer(ComputerNamePhysicalDnsHostname, r);
    r.primary_suffix = computer(ComputerNamePhysicalDnsDomain, r);
    r.search_lists.push_back(
        search(L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
               "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\SearchList"));
    r.search_lists.push_back(
        search(L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
               "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\SearchList"));
    for (const auto &s : r.search_lists)
        if (s.status.rfind("unavailable", 0) == 0)
            r.warnings.push_back("Optional search list metadata " + s.status + ": " + s.source);
}
} // namespace audit
