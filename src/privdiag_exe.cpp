
#include <windows.h>
#include <string>
#include "privdiag/security_summary.h"

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int) {
    std::wstring info = BuildSecuritySummary();
    MessageBoxW(NULL, info.c_str(), L"Security Summary (EXE)", MB_OK | MB_ICONINFORMATION);
    return 0;
}
