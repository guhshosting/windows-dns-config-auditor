// Validation-only helper: runs the complete acquisition under a restricted thread token.
#include "model.h"
#include <windows.h>
#include <sddl.h>
#include <iostream>
int main() {
    HANDLE original = nullptr, restricted = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_IMPERSONATE,
                          &original))
        return 2;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID admin = nullptr;
    if (!AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0,
                                  0, 0, 0, 0, 0, &admin)) {
        CloseHandle(original);
        return 3;
    }
    SID_AND_ATTRIBUTES deny{admin, 0};
    BOOL ok = CreateRestrictedToken(original, DISABLE_MAX_PRIVILEGE, 1, &deny, 0, nullptr, 0,
                                    nullptr, &restricted);
    CloseHandle(original);
    if (!ok) {
        FreeSid(admin);
        return 4;
    }
    PSID medium = nullptr;
    if (!ConvertStringSidToSidW(L"S-1-16-8192", &medium)) {
        FreeSid(admin);
        CloseHandle(restricted);
        return 5;
    }
    TOKEN_MANDATORY_LABEL label{};
    label.Label = {medium, SE_GROUP_INTEGRITY};
    ok = SetTokenInformation(restricted, TokenIntegrityLevel, &label,
                             static_cast<DWORD>(sizeof(label) + GetLengthSid(medium)));
    LocalFree(medium);
    if (!ok || !ImpersonateLoggedOnUser(restricted)) {
        FreeSid(admin);
        CloseHandle(restricted);
        return 6;
    }
    BOOL member = TRUE;
    ok = CheckTokenMembership(nullptr, admin, &member);
    FreeSid(admin);
    CloseHandle(restricted);
    if (!ok || member) {
        RevertToSelf();
        return 7;
    }
    int code = 0;
    try {
        auto result = audit::acquire();
        std::string document = audit::json(result);
        RevertToSelf();
        std::cerr << "Restricted thread verified: Administrators disabled, medium integrity; "
                     "complete acquisition succeeded.\n";
        std::cout << document;
    } catch (...) {
        RevertToSelf();
        code = 8;
    }
    return code;
}
