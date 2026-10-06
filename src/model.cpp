#include "model.h"
#include <limits>
#include <windows.h>
namespace audit {
std::string utf8(const std::wstring &value) {
    if (value.empty())
        return {};
    if (value.size() > static_cast<size_t>((std::numeric_limits<int>::max)()))
        throw std::runtime_error("Unicode text too large");
    const int length = static_cast<int>(value.size());
    const int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), length, nullptr,
                                      0, nullptr, nullptr);
    if (!n)
        throw std::runtime_error("Invalid Unicode configuration text");
    std::string out(static_cast<size_t>(n), '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), length, out.data(), n,
                             nullptr, nullptr))
        throw std::runtime_error("Unicode conversion failed");
    return out;
}
} // namespace audit
