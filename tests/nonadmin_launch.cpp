// Validation-only launcher. It is not linked into or installed with the auditor.
#include <windows.h>
#include <sddl.h>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
namespace {
struct Handle {
    HANDLE value = nullptr;
    ~Handle() {
        if (value)
            CloseHandle(value);
    }
    Handle() = default;
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
};
struct LocalDeleter {
    void operator()(void *p) const {
        if (p)
            LocalFree(p);
    }
};
struct SidDeleter {
    void operator()(void *p) const {
        if (p)
            FreeSid(p);
    }
};
void require(BOOL ok) {
    if (!ok)
        throw std::runtime_error("Windows restricted-token validation API failed: " +
                                 std::to_string(GetLastError()));
}
int run(const wchar_t *executable) {
    Handle original, token;
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &original.value));
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID rawAdmin = nullptr;
    require(AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                     0, 0, 0, 0, 0, 0, &rawAdmin));
    std::unique_ptr<void, SidDeleter> admin(rawAdmin);
    SID_AND_ATTRIBUTES deny{admin.get(), 0};
    require(CreateRestrictedToken(original.value, DISABLE_MAX_PRIVILEGE, 1, &deny, 0, nullptr, 0,
                                  nullptr, &token.value));
    DWORD bytes = 0;
    GetTokenInformation(token.value, TokenUser, nullptr, 0, &bytes);
    if (!bytes)
        throw std::runtime_error("Token user size unavailable");
    std::vector<unsigned char> data(bytes);
    require(GetTokenInformation(token.value, TokenUser, data.data(), bytes, &bytes));
    LPWSTR rawSid = nullptr;
    require(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(data.data())->User.Sid, &rawSid));
    std::unique_ptr<void, LocalDeleter> userSid(rawSid);
    const std::wstring acl = L"D:(A;;GA;;;SY)(A;;GA;;;" + std::wstring(rawSid) + L")";
    PSECURITY_DESCRIPTOR rawDescriptor = nullptr;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(), SDDL_REVISION_1,
                                                                 &rawDescriptor, nullptr));
    std::unique_ptr<void, LocalDeleter> descriptor(rawDescriptor);
    PACL dacl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    require(GetSecurityDescriptorDacl(descriptor.get(), &present, &dacl, &defaulted));
    if (!present || !dacl)
        throw std::runtime_error("Token default DACL unavailable");
    // Give the user access to its process objects after Administrators becomes deny-only.
    TOKEN_DEFAULT_DACL defaultDacl{dacl};
    require(SetTokenInformation(token.value, TokenDefaultDacl, &defaultDacl, sizeof(defaultDacl)));
    PSID rawMedium = nullptr;
    require(ConvertStringSidToSidW(L"S-1-16-8192", &rawMedium));
    std::unique_ptr<void, LocalDeleter> medium(rawMedium);
    TOKEN_MANDATORY_LABEL label{{medium.get(), SE_GROUP_INTEGRITY}};
    require(SetTokenInformation(token.value, TokenIntegrityLevel, &label,
                                static_cast<DWORD>(sizeof(label) + GetLengthSid(medium.get()))));
    require(ImpersonateLoggedOnUser(token.value));
    BOOL member = TRUE;
    const BOOL checked = CheckTokenMembership(nullptr, admin.get(), &member);
    const BOOL reverted = RevertToSelf();
    require(checked);
    require(reverted);
    if (member)
        throw std::runtime_error("Administrators membership remained enabled");
    std::fputs("Verified restricted child token: Administrators disabled, medium integrity.\n",
               stderr);
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    require(SetHandleInformation(si.hStdOutput, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT));
    require(SetHandleInformation(si.hStdError, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT));
    PROCESS_INFORMATION pi{};
    std::wstring command = L"\"" + std::wstring(executable) + L"\" --json";
    require(CreateProcessAsUserW(token.value, nullptr, command.data(), nullptr, nullptr, TRUE,
                                 CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi));
    Handle process;
    process.value = pi.hProcess;
    CloseHandle(pi.hThread);
    if (WaitForSingleObject(process.value, 30000) != WAIT_OBJECT_0)
        throw std::runtime_error("Restricted child did not finish within 30 seconds");
    DWORD code = 1;
    require(GetExitCodeProcess(process.value, &code));
    std::fprintf(stderr, "Child exit %lu\n", code);
    return static_cast<int>(code);
}
} // namespace
int wmain(int argc, wchar_t **argv) {
    if (argc != 2)
        return 2;
    try {
        return run(argv[1]);
    } catch (const std::exception &e) {
        std::fprintf(stderr, "%s\n", e.what());
        return 3;
    } catch (...) {
        return 4;
    }
}

