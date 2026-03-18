# Lesson 20 — Malware Analysis
## Basic Static Analysis — Lab + Answers

> **Password for sample archives:** `infected`

---

## Exercise 1: File Identification

| Field    | Details              |
|----------|----------------------|
| Duration | 15 minutes           |
| Folder   | Lab 1                |
| Files    | All files in folder  |

Using the tools we learned, identify the file type of each sample and check using online resources (VirusTotal, etc.) whether the files are malicious or not.

### ✔ Answers — File Type Identification

| Filename            | File Type                        |
|---------------------|----------------------------------|
| Sample-Lab-3-1-1    | EXE — Windows Executable         |
| Sample-Lab-3-1-2    | ZIP — Archive                    |
| Sample-Lab-3-1-3    | PNG — Image                      |
| Sample-Lab-3-1-4    | 7zip — Archive                   |
| Sample-Lab-3-1-5    | DLL — Dynamic Link Library       |
| Sample-Lab-3-1-6    | COFF — Object File               |
| Sample-Lab-3-1-7    | TEXT — Plain Text File           |
| Sample-Lab-3-1-8    | HTML — Web Page                  |
| Sample-Lab-3-1-9    | DOCX — Word Document             |
| Sample-Lab-3-1-10   | PPTX — PowerPoint Presentation   |
| Sample-Lab-3-1-11   | XLSX — Excel Spreadsheet         |

---

## Exercise 2: Deep File Analysis

| Field    | Details                          |
|----------|----------------------------------|
| Duration | 60 minutes                       |
| Folder   | Lab 2                            |
| Files    | `Lab01-01.dll` and `Lab01-01.exe`|

---

### Q1. What is the type of files?

> **Answer:**
> - `Lab01-01.dll` → **DLL** (Dynamic Link Library)
> - `Lab01-01.exe` → **EXE** (Windows Executable / PE32)

---

### Q2. Upload the files to VirusTotal. Does either file match any existing antivirus signatures?

Steps: Go to [virustotal.com](http://www.VirusTotal.com/) → Upload each file → View the **Detection** tab.

> **Answer:**
> Both files match multiple antivirus signatures on VirusTotal.
> They are flagged as malicious by the majority of AV engines.
> You can also search by SHA256 hash if you prefer not to upload directly.

---

### Q3. When were these files compiled?

> **Answer:**
> - `Lab01-01.dll` → Compile timestamp: **2010/12/19**
> - `Lab01-01.exe` → Compile timestamp: **2010/12/19**
>
> _How to find: Use PEview, PEStudio, or CFF Explorer → PE Header → TimeDateStamp_

---

### Q4. Is it packed? If yes, unpack it.

> **Answer:**
> - `Lab01-01.dll` → **No indication of packing** (normal entropy, normal import table)
> - `Lab01-01.exe` → **No indication of packing**
>
> Verification: Use Detect-It-Easy (DIE) or PEiD.
> Entropy values appear normal (5.0–6.5 range). Import table is populated normally.

---

### Q5. Do any imports hint at what this malware does?

Imports suggest the program searches for and copies files, creates processes, and operates over a network.

#### Lab01-01.dll — Imports

| Library       | Function          | Significance                              |
|---------------|-------------------|-------------------------------------------|
| KERNEL32.dll  | `CreateMutexA()`  | Prevents multiple instances; mutex is IOC |
| KERNEL32.dll  | `CreateProcessA()`| Executes processes — remote command exec  |
| KERNEL32.dll  | `Sleep()`         | Delays execution — evasion / beacon timing|
| MSVCRT.dll    | `strncmp()`       | String comparison — likely command parsing|
| WS2_32.dll    | *(by ordinal)*    | Network operations — socket / C2 comms    |

#### Lab01-01.exe — Imports

| Library       | Function           | Significance                            |
|---------------|--------------------|-----------------------------------------|
| KERNEL32.dll  | `CopyFileA()`      | Copies files — deploys `kerne132.dll`   |
| KERNEL32.dll  | `FindFirstFileA()` | Enumerate filesystem — file search      |
| KERNEL32.dll  | `FindNextFileA()`  | Iterate through search results          |

---

### Q6. Extract the strings and list the ones that seem important.

#### Lab01-01.dll — Key Strings

```
000000026018   sleep           → backdoor command: tells malware to sleep
000000026020   hello           → backdoor command: keep-alive / ping
000000026028   127.26.152.13   → C2 IP ADDRESS ← critical IOC
000000026038   SADFHUHF        → likely mutex name to prevent re-infection
```

#### Lab01-01.exe — Key Strings

```
000000003010   kerne132.dll                         → TYPOSQUAT: '1' instead of 'l'
000000003020   kernel32.dll                         → legitimate DLL name reference
00000000304C   C:\windows\system32\kerne132.dll     → drop path for malicious DLL
00000000307C   Lab01-01.dll                         → reference to sibling DLL
00000000308C   C:\Windows\System32\Kernel32.dll     → legitimate path reference
0000000030B0   WARNING_THIS_WILL_DESTROY_YOUR_MACHINE  → destructive payload warning!
```

---

### Q7. Are there any other files or host-based indicators to look for on infected systems?

> **Answer:**
>
> 1. **File:** `kerne132.dll` in `C:\Windows\System32\`
>    _(Note the digit `1` instead of letter `l` — typosquatting technique)_
>
> 2. **String/Mutex:** `WARNING_THIS_WILL_DESTROY_YOUR_MACHINE`
>
> 3. **Network string in memory:** `127.26.152.13` (C2 IP embedded in `Lab01-01.dll`)
>
> 4. **Backdoor command strings in memory:** `exec`, `sleep`, `hello`
>    _(Commands the C2 server can issue to the backdoor)_

---

### Q8. What network-based indicators could be used to find this malware on infected machines?

> **Answer:**
>
> - **Primary IOC:** Outbound TCP connections to `127.26.152.13`
> - **Detection rule:** Alert on any internal host communicating with `127.26.152.13`
> - **Protocol:** Likely custom protocol over raw TCP (WS2_32 imported by ordinal)
> - **Additional:** Monitor for beacon-like traffic pattern to this IP
>
> Note: `127.26.152.13` appears in the DLL strings — the EXE loads the DLL to enable C2.

---

### Q9. What would you guess is the purpose of these files?

> **Answer:**
>
> #### `Lab01-01.exe` — Dropper
> - Searches the filesystem using `FindFirstFile` / `FindNextFile`
> - Copies `Lab01-01.dll` to `C:\Windows\System32\kerne132.dll`
>   _(masquerading as the legitimate `kernel32.dll` by substituting `l` with `1`)_
>
> #### `Lab01-01.dll` (deployed as `kerne132.dll`) — Backdoor
> - Connects to C2 server at `127.26.152.13` via raw socket (WS2_32)
> - Accepts remote commands from the attacker:
>   - `exec` — execute commands on the infected system
>   - `sleep` — pause/delay execution
>   - `hello` — keep-alive / ping
> - Creates mutex `SADFHUHF` to prevent multiple instances
> - Contains `WARNING_THIS_WILL_DESTROY_YOUR_MACHINE` — potential destructive payload
>
> #### Overall Conclusion
> A **dropper + backdoor** pair. The EXE installs a network-enabled backdoor DLL,
> allowing the attacker to remotely execute commands on the infected system.
> The DLL masquerades as a core Windows system file to evade detection.

---

## Additional Resources

- **Malware Analysis Playlist (YouTube):**
  https://youtube.com/playlist?list=PLBf0hzazHTGMSlOI2HZGc08ePwut6A2Io

- **Static Malware Examination (Medium article):**
  https://th3m4rk5man.medium.com/static-malware-examination-5614c5773d22

- **Additional YouTube tutorial:**
  https://youtu.be/KNe4hTVhpPQ
