#include "model.h"
#include <iostream>
#include <windows.h>
namespace {
void output(const std::string &text, DWORD channel) {
    HANDLE h = GetStdHandle(channel);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode)) {
        int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                    static_cast<int>(text.size()), nullptr, 0);
        if (!n)
            throw std::runtime_error("Output conversion failed");
        std::wstring wide(static_cast<size_t>(n), L'\0');
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                            static_cast<int>(text.size()), wide.data(), n);
        size_t pos = 0;
        while (pos < wide.size()) {
            DWORD written = 0;
            const DWORD count = static_cast<DWORD>((std::min)(wide.size() - pos, size_t{16384}));
            if (!WriteConsoleW(h, wide.data() + pos, count, &written, nullptr) || !written)
                throw std::runtime_error("Console write failed");
            pos += written;
        }
    } else {
        size_t pos = 0;
        while (pos < text.size()) {
            DWORD written = 0;
            const DWORD count = static_cast<DWORD>((std::min)(text.size() - pos, size_t{16384}));
            if (!WriteFile(h, text.data() + pos, count, &written, nullptr) || !written)
                throw std::runtime_error("Output write failed");
            pos += written;
        }
    }
}
} // namespace
int wmain(int argc, wchar_t **argv) {
    try {
        std::vector<std::wstring> args;
        for (int i = 1; i < argc; ++i)
            args.emplace_back(argv[i]);
        const auto options = audit::parse(args);
        if (options.help) {
            output(
                "Usage: windows-dns-config-auditor [--all] [--json]\n       "
                "windows-dns-config-auditor --help | --version\nRead-only local DNS configuration "
                "audit. No DNS queries or connectivity tests.\n--all includes inactive adapter "
                "details in human output. JSON always includes all adapters.\nExit codes: 0 "
                "completed, 2 usage, 3 acquisition failure, 4 internal failure.\n",
                STD_OUTPUT_HANDLE);
            return 0;
        }
        if (options.version) {
            output("windows-dns-config-auditor 1.0.0\n", STD_OUTPUT_HANDLE);
            return 0;
        }
        const auto result = audit::acquire();
        output(options.json ? audit::json(result) : audit::human(result, options.all),
               STD_OUTPUT_HANDLE);
        return 0;
    } catch (const std::invalid_argument &e) {
        std::cerr << e.what() << "; use --help\n";
        return 2;
    } catch (const audit::ApiError &e) {
        std::cerr << e.what() << '\n';
        return 3;
    } catch (const std::exception &e) {
        std::cerr << "Internal failure: " << e.what() << '\n';
        return 4;
    } catch (...) {
        std::cerr << "Unexpected internal failure\n";
        return 4;
    }
}
