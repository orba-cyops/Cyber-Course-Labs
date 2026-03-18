# Lesson 21 – Malware Analysis: Basic Dynamic Analysis
## Lab Guideline & Full Answers

> **Lab File:** `financials-xls.exe` (inside `lab/` folder, zip password: `infected`)
> **Estimated Time:** 90 minutes

---

## Overview

In this lab you will perform a **full malware analysis** on a suspicious executable disguised as a spreadsheet. Your report must cover:

1. **Static Analysis** – Examine the file without running it
2. **Dynamic Analysis** – Execute the file in a safe sandbox and observe behavior

**Key IoC categories to document:**
- URLs, IPs, domains
- Files created / modified
- Registry keys
- Processes spawned
- HTTP / DNS requests
- Hashes (MD5, SHA-256)

---

## Part 1 – Static Analysis

### Step 1.1 – Compute File Hash

**Why:** Hashes uniquely identify a file and allow you to look it up on threat intelligence platforms.

**Tools:** `CertUtil`, `sha256sum`, `HashMyFiles`, or `VirusTotal`

**Guideline:**
1. Open a terminal and run:
   ```
   certutil -hashfile financials-xls.exe SHA256
   ```
2. Record the hash and search it on [VirusTotal](https://www.virustotal.com) and [Hybrid-Analysis](https://www.hybrid-analysis.com).

### ✅ Answer – Hashes

| State | SHA-256 Hash |
|-------|-------------|
| **Packed (original)** | `f09ffe74770a7229ddef667bc95fa73e0886adf8739cdfff36101443975e5b5a` |
| **Unpacked** | `726a072434e751b2781d49f4f85ec213b60df0ef6aa6377d5d55fad0171e7de9` |

> **Finding:** The file is **packed** (compressed/obfuscated) – a strong indicator of malicious intent.

---

### Step 1.2 – Detect Packing

**Why:** Packed malware hides its real code. The packer must be identified before deeper analysis.

**Tools:** `PEiD`, `Detect-It-Easy (DIE)`, `ExeinfoPE`

**Guideline:**
1. Open `financials-xls.exe` in **Detect-It-Easy** or **PEiD**.
2. Check if a known packer (UPX, MPRESS, etc.) is detected.
3. If packed, unpack using the appropriate tool (e.g., `upx -d financials-xls.exe`).
4. Re-hash the unpacked file.

### ✅ Answer – Packing
- The binary **is packed**.
- After unpacking, the SHA-256 changes to `726a072...` (see table above), confirming the original binary was obfuscated.

---

### Step 1.3 – PE Header Analysis

**Why:** The PE (Portable Executable) header reveals sections, imports, and suspicious attributes.

**Tools:** `PE-bear`, `PEview`, `CFF Explorer`

**Guideline:**
1. Open the **unpacked** binary in PE-bear / CFF Explorer.
2. Check:
   - **Sections** – Look for suspicious names or permissions (e.g., `.text` with Write+Execute is abnormal).
   - **Imports (DLLs & functions)** – Flag any suspicious API calls.
   - **Resources** – Check for embedded executables, icons, or documents.

### ✅ Answer – PE Analysis

**Suspicious DLLs / Functions to flag:**

| DLL | Suspicious Functions |
|-----|---------------------|
| `kernel32.dll` | `CreateFile`, `WriteFile`, `CopyFile` (file manipulation) |
| `advapi32.dll` | `RegSetValueEx`, `RegOpenKey` (registry manipulation) |
| `wininet.dll` | `InternetOpenUrl`, `InternetConnect` (network activity) |
| `ws2_32.dll` | Socket functions (network connectivity) |

**Section Permissions:** Look for sections flagged as both **writable and executable** — this indicates runtime code unpacking.

---

### Step 1.4 – String Analysis

**Why:** Strings can reveal hardcoded URLs, file paths, registry keys, and error messages.

**Tools:** `Strings` (Sysinternals), `FLOSS`, `BinText`

**Guideline:**
1. Run:
   ```
   strings financials-xls.exe > strings_output.txt
   ```
2. Search for: URLs (`http`, `www`), file paths (`C:\`), registry paths (`SOFTWARE\`), IP addresses, executable names.

### ✅ Answer – Strings (Key Findings)

| Type | Value |
|------|-------|
| **Domain (C2)** | `download.bravesentry.com` |
| **File path** | `C:\Windows\xpupdate.exe` |
| **Registry path** | Related to `Run` keys for persistence |
| **Network protocol** | HTTP GET request strings |

---

## Part 2 – Dynamic Analysis

> ⚠️ **Safety:** Always run malware in an **isolated VM** (e.g., FlareVM / REMnux). Disable network or use a simulator (FakeNet-NG / INetSim). Take a **VM snapshot** before execution.

### Pre-Execution Baseline

Before running the malware, capture the system state:

| Tool | Purpose |
|------|---------|
| **Regshot** | Take a registry/filesystem snapshot (Shot 1) |
| **Autoruns** | Record all auto-start entries |
| **TCPView** | Note current network connections |

---

### Step 2.1 – Process Monitoring (Procmon)

**Tools:** `Process Monitor (Procmon)` – Sysinternals

**Guideline:**
1. Open Procmon and set filters:
   - **Process Name** contains `financials` OR `xpupdate`
   - Show: File System Activity, Registry Activity, Process Activity
2. Run `financials-xls.exe`.
3. Stop capture after ~2 minutes and analyze results.

### ✅ Answer – Procmon Findings

| Activity Type | Finding |
|--------------|---------|
| **File Created** | `C:\Windows\xpupdate.exe` – malware copies itself here |
| **Registry Write** | Persistence key written under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| **Process Spawned** | Child process created from `xpupdate.exe` |

---

### Step 2.2 – Network Traffic Analysis

**Tools:** `FakeNet-NG` or `INetSim`, `TCPView`, `Wireshark`

**Guideline:**
1. Start **FakeNet-NG** or **INetSim** to simulate internet responses.
2. Run the malware.
3. In **TCPView**, observe outbound connections.
4. Export PCAP from FakeNet and open in **Wireshark** to inspect HTTP/DNS.

### ✅ Answer – Network Findings

| Protocol | Destination | Detail |
|----------|-------------|--------|
| **DNS** | `download.bravesentry.com` | DNS resolution attempt |
| **HTTP** | `download.bravesentry.com` | Attempted file download (C2 callback) |
| **TCP** | External IP (simulated by FakeNet) | Outbound connection observed in TCPView |

---

### Step 2.3 – Registry & Persistence (Regshot + Autoruns)

**Guideline:**
1. After running the malware, take **Regshot – Shot 2** and compare with Shot 1.
2. Check **Autoruns** for new entries.

### ✅ Answer – Persistence Mechanism

| Location | Value |
|----------|-------|
| **Registry Key** | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| **Value** | Points to `C:\Windows\xpupdate.exe` |
| **Purpose** | Ensures malware runs on every system reboot |

---

### Step 2.4 – Process Visualization (ProcDOT)

**Tools:** `ProcDOT`

**Guideline:**
1. Export Procmon log as CSV.
2. Load CSV + Wireshark PCAP into ProcDOT.
3. Generate a visual process graph.

### ✅ Answer – ProcDOT Graph
- Graph shows `financials-xls.exe` spawning activity, writing `xpupdate.exe`, touching registry Run keys, and initiating network calls to `download.bravesentry.com`.
- Hash of `xpupdate.exe` = `726a072434e751b2781d49f4f85ec213b60df0ef6aa6377d5d55fad0171e7de9` (**same as unpacked original** – confirmed self-copy).

---

## Part 3 – Conclusions

### What is the malware doing?

| # | Behavior |
|---|---------|
| 1 | **Self-replicates** – copies itself to `C:\Windows\xpupdate.exe` |
| 2 | **Establishes persistence** – writes a registry Run key to survive reboots |
| 3 | **Phones home** – contacts `download.bravesentry.com` to download additional payloads |
| 4 | **Disguise** – uses a double-extension filename (`financials-xls.exe`) to appear like a spreadsheet |

### What kind of malware is this?

> **Classification: Downloader / Dropper**

The malware's primary purpose is to **download additional malicious code** from a remote server (`download.bravesentry.com`). This is consistent with a **downloader** — a first-stage payload that retrieves and executes a secondary, more dangerous payload.

---

## Complete IoC Summary

| Category | IoC |
|----------|-----|
| **Hash (packed)** | `f09ffe74770a7229ddef667bc95fa73e0886adf8739cdfff36101443975e5b5a` |
| **Hash (unpacked / xpupdate.exe)** | `726a072434e751b2781d49f4f85ec213b60df0ef6aa6377d5d55fad0171e7de9` |
| **Domain (C2)** | `download.bravesentry.com` |
| **File dropped** | `C:\Windows\xpupdate.exe` |
| **Registry key** | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| **Malware type** | Downloader |
| **Packing** | Yes (packed original binary) |

---

## Tools Reference

| Tool | Use |
|------|-----|
| VirusTotal | Online hash/URL reputation |
| Hybrid-Analysis | Online sandbox |
| PEiD / DIE | Detect packers |
| CFF Explorer / PE-bear | PE header analysis |
| Strings / FLOSS | Extract strings |
| Procmon | File/registry/process monitoring |
| FakeNet-NG / INetSim | Network simulation |
| TCPView | Live network connections |
| Regshot | Registry diff |
| Autoruns | Persistence analysis |
| Wireshark | PCAP / packet analysis |
| ProcDOT | Process visualization |

---

## Additional Resources

- [Malware Analysis Course Video 1](https://youtu.be/k4_l1-SHtu8?si=vLnZ7RhopFWIHCqB)
- [Malware Analysis Course Video 2](https://youtu.be/2Psiwj5G0to?si=QO4L144zr9YBZRjv)
- [Introduction to Malware Analysis – 101.school](https://101.school/courses/introduction-to-malware-analysis/modules/1-introduction-to-malware-analysis/units/1-importance-of-malware-analysis)
