# PrivDialog (Test DLL / EXE)

PrivDialog is a small Windows-only test utility that displays the current process's security and token information in a dialog box. The repository includes a minimal EXE and DLL that use Windows APIs to read and format token data.

## What it shows
- User SID
- UAC elevation (whether the process is elevated)
- Integrity level (Low / Medium / High / System)
- Privilege list (Enabled / Disabled)

## Notes
- Token information is retrieved using `OpenProcessToken` and `GetTokenInformation`.
- Some privilege name lookups may fail depending on system policy or environment.

## License
Apache License 2.0. See [LICENSE](LICENSE).

