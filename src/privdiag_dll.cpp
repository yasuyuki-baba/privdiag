
#include <windows.h>
#include <string>
#include "privdiag/security_summary.h"

extern "C" __declspec(dllexport) void ShowTestDialog() {
    std::wstring info = BuildSecuritySummary();
    MessageBoxW(NULL, info.c_str(), L"Security Summary (DLL)", MB_OK | MB_ICONINFORMATION);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Optional: show at load time (commented to avoid side-effects)
        // ShowTestDialog();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
