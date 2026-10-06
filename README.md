# windows-dns-config-auditor

> Runtime prerequisite for the exact qualified EXE: Microsoft Visual C++ x64 Redistributable is required when the imported runtime DLLs are absent. This supersedes any static-CRT/no-redistributable description of a source build below.


> Release context: see [qualified platforms, runtime requirements and package scope](RELEASE-QUALIFICATION.md).


Version 1.0.0. Native Windows C++17 command-line auditor of **local DNS configuration**. It never tests DNS servers or resolves names. MIT licensed.

```
windows-dns-config-auditor
windows-dns-config-auditor --all
windows-dns-config-auditor --json
windows-dns-config-auditor --help
windows-dns-config-auditor --version
```

Default human output shows system DNS information, operationally up interfaces, ordered numeric DNS server addresses, suffix and registration settings, findings, and limitations. Inactive adapters are counted; `--all` expands their configuration details. Findings include all acquired adapters and identify them by adapter ID. JSON always includes every acquired adapter. Exit codes: 0 audit completed (including findings and optional metadata warnings), 2 usage error, 3 essential network configuration API failure, 4 internal failure. Errors go to stderr; JSON stdout contains one UTF-8 document without a BOM. Console output uses Unicode Windows console APIs; redirected output is UTF-8.

## Configuration sources

[GetAdaptersAddresses](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses) supplies adapter identity, description, friendly name, IPv4/IPv6 indices, LUID, numeric interface type, operational state, protocol-enabled flags, DNS server linked list and connection-specific DNS suffix. Addresses stay numeric; IPv6 is displayed in valid uncompressed hexadecimal notation with a decimal `%scope` when present. Server list order is preserved exactly as returned, without promising Windows query selection order. Operationally up means the API reports `IfOperStatusUp`; it does not prove connectivity. No MAC addresses are collected.

The documented [adapter flags](https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh) expose dynamic DNS enabled and register adapter suffix settings. These are configuration flags, not proof of actual registration, DHCP behavior or effective policy. No updates are triggered.

[GetComputerNameExW](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getcomputernameexw) with physical DNS hostname/domain supplies system identity and primary suffix, avoiding cluster virtual identity. Missing optional names produce warnings.

`DnsQueryConfig` documents [DnsConfigSearchList as not implemented](https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsqueryconfig). Therefore the only Registry reads are `REG_SZ` SearchList values at:

- `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\SearchList`: explicit local suffix list, documented in [Microsoft configuration guidance](https://learn.microsoft.com/troubleshoot/windows-client/networking/configure-domain-suffix-search-list-domain-name-system-clients).
- `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\SearchList`: policy suffix list, documented by [ADMX DNS client policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-dnsclient).

Reads use `RegGetValueW` and the 64-bit view. Raw values and exact sources are reported independently. Missing values are `absent`; access denial, unexpected types, oversized values or races are `unavailable` with warnings. No undocumented Registry enumeration or inference is used. An absent/empty explicit list does not mean Windows has no suffix behavior. The utility does not synthesize an effective list, evaluate precedence, expand devolution, or reconstruct all suffixes Windows might try.

## Scope and safety

Application code contains no intentional network communication or hostname-resolution functionality. It creates no communication sockets and contains no resolver component. Its runtime does not invoke command-line utilities, PowerShell, WMI or external processes. It reads supported local APIs and the two justified Registry values only. It does not change DNS, adapters, routes, cache, DHCP, NRPT, DoH, services or Registry, and never auto-elevates. The executable manifest requests `asInvoker`; optional metadata degrades gracefully.

Server lists do not fully predict resolution decisions: NRPT, Group Policy, VPN software, enterprise configuration, interface selection and resolver behavior may intervene. Deep NRPT and DoH configuration auditing are out of scope for 1.0.0. The application does not determine reachability, latency, answers, transport, registration success or server health. Public/private servers are not judged. Loopback and link-local servers are factual findings, not errors. The snapshot is not atomic.

## JSON contract

Schema `1.0` and application `1.0.0` are distinct version strings. Top-level fields: `schema_version`, `application_version`, `system`, `suffix_configuration`, `adapters`, `findings`, `warnings`, `limitations`. The adapter `dns_servers` array preserves API order. Each entry includes address text, family (`IPv4`, `IPv6`, `unknown`), scope ID and classification flags. Malformed/unsupported socket addresses have `valid:false`, empty address and unknown family. LUID is a decimal string to avoid JSON numeric precision loss. Empty suffix strings mean empty/unavailable (consult warnings for acquisition failures). Search-list records carry status and raw text, not an effective resolver order. Finding codes are machine-readable; messages are explanatory. Consumers should tolerate additional fields and unknown finding codes within this schema major version.

## Compatibility and build

Targets Windows 10, Windows 11 and corresponding supported Windows Server generations, x64, using the Windows 10+ SDK and MSVC. Only actual runtime-tested versions are listed in VALIDATION.md. No third-party runtime library dependencies beyond the MSVC runtime and Windows system libraries.

Run from an x64 MSVC Developer Command Prompt with CMake 3.24+ and Ninja:

```
cmake -S . -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
ctest --test-dir build-release --output-on-failure
cmake --install build-release --prefix install
```

Use separate build directories for Debug, Release, `-DWSA_ANALYZE=ON`, and `-DWSA_ASAN=ON` (RelWithDebInfo). The ASan runtime must be on PATH for tests. `/W4 /WX` are always enabled for production targets. `scripts/dev.cmd` is a convenience wrapper for this validation machine's VS installation; adapt the path for your environment. Build/test scripts may use shells; the application does not.

Synthetic tests cover numeric IPv4/IPv6, scope, loopback, duplicate/mixed lists, link-local, empty and inactive adapters, differing active lists, suffixes, Unicode, malformed addresses, JSON escaping and CLI. Live checks never change DNS settings. See [VALIDATION.md](VALIDATION.md) for exact validation evidence and limits.
The machine-readable JSON Schema is [schemas/schema-v1.0.json](schemas/schema-v1.0.json). The installed share directory also contains the schema and validation report.
