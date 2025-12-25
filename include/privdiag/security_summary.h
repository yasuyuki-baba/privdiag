
#pragma once
#include <windows.h>
#include <sddl.h>
#include <string>
#include <vector>

static std::wstring GetLastErrorMessage(DWORD err) {
    LPWSTR buf = nullptr;
    DWORD len = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                               NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&buf, 0, NULL);
    std::wstring msg = (len && buf) ? std::wstring(buf) : L"Unknown error";
    if (buf) LocalFree(buf);
    return msg;
}

static std::wstring SidToString(PSID sid) {
    LPWSTR sidStr = NULL;
    if (ConvertSidToStringSidW(sid, &sidStr)) {
        std::wstring s(sidStr);
        LocalFree(sidStr);
        return s;
    }
    return L"(SID conversion failed)";
}

static std::wstring GetIntegrityLevelString(DWORD il) {
    if (il >= SECURITY_MANDATORY_SYSTEM_RID) return L"System";
    if (il >= SECURITY_MANDATORY_HIGH_RID) return L"High";
    if (il >= SECURITY_MANDATORY_MEDIUM_RID) return L"Medium";
    if (il >= SECURITY_MANDATORY_LOW_RID) return L"Low";
    return L"Unknown";
}

static std::wstring PrivilegeLuidToName(LUID luid) {
    WCHAR name[256];
    DWORD cch = 256;
    if (LookupPrivilegeNameW(NULL, &luid, name, &cch)) {
        return std::wstring(name, cch);
    }
    return L"UnknownPrivilege";
}

// Forward declaration so BuildSecuritySummary can call it on all compilers
static std::wstring GetThisModulePath();


static std::wstring BuildSecuritySummary() {
    HANDLE hToken = NULL;
    std::wstring out;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        out = L"OpenProcessToken failed: " + GetLastErrorMessage(GetLastError());
        return out;
    }

    // User SID
    DWORD len = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &len);
    std::vector<BYTE> bufUser(len);
    if (!GetTokenInformation(hToken, TokenUser, bufUser.data(), len, &len)) {
        out += L"TokenUser failed: " + GetLastErrorMessage(GetLastError()) + L"\n";
    } else {
        TOKEN_USER* tu = (TOKEN_USER*)bufUser.data();
        out += L"User SID: " + SidToString(tu->User.Sid) + L"\n";
    }

    // Elevation
    TOKEN_ELEVATION elevation{};
    len = sizeof(elevation);
    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &len)) {
        out += std::wstring(L"Elevated: ") + (elevation.TokenIsElevated ? L"Yes" : L"No") + L"\n";
    }

    // Integrity level
    len = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &len);
    std::vector<BYTE> bufIL(len);
    if (GetTokenInformation(hToken, TokenIntegrityLevel, bufIL.data(), len, &len)) {
        TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)bufIL.data();
        DWORD il = *GetSidSubAuthority(tml->Label.Sid, (DWORD)(*GetSidSubAuthorityCount(tml->Label.Sid) - 1));
        out += L"Integrity: " + GetIntegrityLevelString(il) + L" (" + std::to_wstring(il) + L")\n";
    }

    // Privileges
    len = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &len);
    std::vector<BYTE> bufPriv(len);
    if (GetTokenInformation(hToken, TokenPrivileges, bufPriv.data(), len, &len)) {
        TOKEN_PRIVILEGES* tp = (TOKEN_PRIVILEGES*)bufPriv.data();
        out += L"Privileges (" + std::to_wstring(tp->PrivilegeCount) + L"):\n";
        for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
            LUID_AND_ATTRIBUTES la = tp->Privileges[i];
            std::wstring name = PrivilegeLuidToName(la.Luid);
            bool enabled = (la.Attributes & SE_PRIVILEGE_ENABLED) != 0;
            out += L"  - " + name + L" : " + (enabled ? L"Enabled" : L"Disabled") + L"\n";
        }
    }

    CloseHandle(hToken);
    // Append module path (full path to this DLL or EXE)
    out += L"Module: " + GetThisModulePath() + L"\n";
    return out;
}

static std::wstring GetThisModulePath() {
    HMODULE hMod = NULL;
    // Use the function address to get the module handle for this DLL/EXE
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)(void*)&GetThisModulePath, &hMod)) {
        WCHAR buf[MAX_PATH];
        DWORD n = GetModuleFileNameW(hMod, buf, MAX_PATH);
        if (n) return std::wstring(buf, n);
    }
    // Fallback to the main module (EXE)
    WCHAR buf2[MAX_PATH];
    DWORD n2 = GetModuleFileNameW(NULL, buf2, MAX_PATH);
    if (n2) return std::wstring(buf2, n2);
    return L"(unknown module)";
}

