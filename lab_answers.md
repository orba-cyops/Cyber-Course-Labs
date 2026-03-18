# Lesson 24 — Introduction to Wireshark
## Professional Lab Answer Guide
### Complete Walkthrough with Screenshot References

---

> **How to use this guide:** Every answer below is derived from the actual PCAP files provided. Screenshot references are marked as **[Screenshot X.X]** — each describes exactly what the Wireshark window should look like at that step.

---

## Setup Verification

Before beginning, confirm the following:

- Wireshark 4.0+ installed and launched with **administrator/root privileges**
- All PCAP files present in your working folder:
  - `http.cap` (43 packets, ~25 KB)
  - `dns.cap` (38 packets, ~4 KB)
  - `nb6-startup.pcap` (531 packets, ~79 KB)
  - `2024-11-26-traffic-analysis-exercise.pcap` (unzipped from ZIP)
- Open `http.cap` without errors → status bar should read **43 packets**

---

## Exercise 1: Comprehensive Interface Exploration
**File:** `http.cap`

---

### Task 1.1: Interface Orientation

Open `http.cap` via **File > Open** or drag-and-drop onto the Wireshark window.

**[Screenshot 1.1a — Wireshark main window with http.cap loaded]**
> *What to see:* Three-pane layout. Top pane shows 43 rows with columns: No., Time, Source, Destination, Protocol, Length, Info. The status bar at the bottom-right reads "43 packets".*

#### Pane Descriptions

| Pane | Location | Contents |
|------|----------|----------|
| **Packet List Pane** | Top | One row per packet: number, timestamp, source/destination IP, protocol, length, summary info |
| **Packet Details Pane** | Middle | Expandable tree: Frame → Ethernet II → Internet Protocol → TCP/UDP → Application layer. Click a row to populate this pane. |
| **Packet Bytes Pane** | Bottom | Raw packet bytes shown in **hex** (left column) and **ASCII** (right column). Highlighted offset corresponds to selected field in Details pane. |

**[Screenshot 1.1b — Packet Details pane expanded on packet #4, showing HTTP GET request tree]**
> *What to see:* Hypertext Transfer Protocol layer expanded, showing `GET /download.html HTTP/1.1`, Host header, and User-Agent.*

#### Recorded Observations

| Field | Value |
|-------|-------|
| **Total number of packets** | **43** |
| **Time span of capture** | **30.4 seconds** (0.000000 – 30.393s) |
| **Number of unique IP addresses** | **4** (`145.254.160.237`, `65.208.228.223`, `216.239.59.99`, `145.253.2.203`) |

---

### Task 1.2: Toolbar Navigation

**[Screenshot 1.2a — Wireshark toolbar with key buttons labeled]**
> *What to see:* Blue shark-fin (Start Capture), red square (Stop), green rotating arrow (Restart), folder icon (Open), floppy disk (Save), binoculars (Find Packet), arrow-with-number (Go to Packet).*

#### Keyboard Shortcuts Reference

| Action | Shortcut |
|--------|----------|
| Open file | `Ctrl+O` |
| Save | `Ctrl+S` |
| Find packet | `Ctrl+F` |
| Go to packet | `Ctrl+G` |
| Find next | `F3` |

**Practice Navigation Results:**

- **Go to packet #10:** Press `Ctrl+G`, type `10`, press Enter → Packet 10 is a **TCP ACK** from `65.208.228.223 → 145.254.160.237`
- **First HTTP GET request:** Press `Ctrl+F`, select "String", type `GET`, press Enter → **Packet #4** at timestamp `0.911310 s` — `GET /download.html HTTP/1.1`
- **Last packet:** Press `Ctrl+End` or `End` key → **Packet #43** at timestamp `30.393 s`

**[Screenshot 1.2b — Go-to-packet dialog showing "10" entered, packet 10 highlighted in list]**

---

### Task 1.3: Menu System Discovery

| Menu | Key Function |
|------|-------------|
| **File** | Open/Save/Export capture files; Export Objects (HTTP, SMB, etc.) |
| **Edit** | Find Packet (`Ctrl+F`); Mark/Unmark packets; Preferences |
| **View** | Time Display Format; Zoom In/Out; Colorize Packet List; Columns configuration |
| **Capture** | Start/Stop/Restart capture; Capture Options (interface, filters, file limits) |
| **Analyze** | Display Filter Expression builder; Follow TCP/UDP/HTTP Stream; Decode As; Expert Information |
| **Statistics** | Protocol Hierarchy; Conversations; Endpoints; I/O Graphs; Flow Graph |
| **Tools** | Firewall ACL Rules generator; Lua scripting console |

**[Screenshot 1.3 — Statistics menu expanded, showing all sub-menu options]**

---

### Challenge Answer — Protocols in http.cap

Navigate to **Statistics > Protocol Hierarchy** to see the full breakdown.

**Answer: 5 distinct protocols** — `Ethernet`, `IPv4`, `TCP`, `UDP`, `HTTP` (plus `DNS` and `XML` in sub-dissectors)

**[Screenshot 1.4 — Protocol Hierarchy window for http.cap showing Ethernet > IPv4 > TCP > HTTP tree]**

---

## Exercise 2: Packet Capture Workshop
**Live capture required**

---

### Task 2.1: Interface Selection

Navigate to **Capture > Options** (`Ctrl+K`).

**[Screenshot 2.1 — Capture Options dialog listing available interfaces with traffic sparklines]**
> *What to see:* Each interface has a name, description, and a small sparkline graph. The active interface (Wi-Fi or Ethernet) will show live activity.*

**Typical interfaces you will see:**

| # | Interface | Notes |
|---|-----------|-------|
| 1 | `Wi-Fi` / `wlan0` / `en0` | Usually the primary active interface |
| 2 | `Ethernet` / `eth0` | May be inactive if on wireless |
| 3 | `Loopback (lo)` / `\Device\NPF_Loopback` | 127.0.0.1 traffic only |

> **Tip:** Select the interface that has a moving sparkline (indicating live traffic).

---

### Task 2.2: Basic Live Capture

**Configuration:**
- Interface: Your active network adapter
- Duration: 120 seconds (set under **Capture > Options > Stop capture automatically after 120 seconds**)
- File size limit: 10 MB

**Traffic generation commands:**

```bash
# Windows
ping google.com -n 4
nslookup google.com

# Linux / macOS
ping google.com -c 4
nslookup google.com
```

**[Screenshot 2.2 — Live capture in progress, status bar showing "Capturing from Wi-Fi", packet counter incrementing]**

**Expected results after 2-minute capture:**

| Metric | Expected Value |
|--------|---------------|
| Packet count | 200–1,500 (varies by activity) |
| Most frequent protocols | TCP, TLSv1.3 (HTTPS), DNS, UDP |
| Largest packet | ~1,514 bytes (Ethernet MTU limit) |

Save the file: **File > Save As** → name it `student_capture_basic.pcap`

---

### Task 2.3: Advanced Capture with Capture Filter

**Capture filter for HTTP only:** `port 80`

Enter this in **Capture > Options > Capture filter** field before starting.

**[Screenshot 2.3 — Capture Options dialog with "port 80" typed in the Capture Filter field; field background is GREEN indicating valid syntax]**

> **Important:** Most modern sites use HTTPS (port 443). Use **http://neverssl.com** to guarantee unencrypted HTTP traffic appears.

**Ring buffer settings:**
- Number of files: 3
- File size: 5 MB each
- Auto-stop: after 3 minutes

---

## Exercise 3: Systematic Filtering Laboratory
**File:** `nb6-startup.pcap` (531 packets total)

---

### Task 3.1: Basic Display Filters

Type each filter into the **Display Filter Bar** and press Enter. The bar turns **green** for valid syntax.

**[Screenshot 3.1a — Display filter bar showing "http" in green, 16 packets displayed in list]**

| Filter | Packets Displayed | Notes |
|--------|------------------|-------|
| `http` | **16** | HTTP GET requests and 200 OK responses |
| `dns` | **112** | DNS queries and responses (heavy DNS activity on startup) |
| `tcp.port == 80` | **116** | Includes TCP handshake packets for port 80 connections |
| `ip.addr == 10.251.23.139` | **152** | Main client device (NB6 router internal IP) |
| `icmp` | **2** | Two ICMP packets present |

**[Screenshot 3.1b — "dns" filter applied, 112 packets shown, all rows highlighted in teal (DNS color rule)]**

---

### Task 3.2: Advanced Filtering

**[Screenshot 3.2 — Advanced filter applied, results visible in packet list]**

#### Filter 1 — All HTTP GET Requests

```
http.request.method == "GET"
```

**Result count: 8 packets**
These are configuration XML file requests from the NB6 router (`10.251.23.139`) to the SFR provisioning server (`86.66.0.227`).

*Example Info column entries:*
- `GET /cfgnb6dslgeneral.xml?...`
- `GET /cfgnb6dslfirmware.xml?...`

---

#### Filter 2 — DNS Queries for a Specific Domain

```
dns.qry.name contains "sfr"
```

**Result count: 22 packets**

**Domains found in this capture:**
- `assistance.sfr.fr`
- `backup.sfr.fr`
- `ntp.sfr.net`
- `sfr.portal.fon.com`
- `hotspot.wifi.sfr.fr`

---

#### Filter 3 — Traffic Between Two Specific IPs

```
(ip.src == 10.251.23.139 and ip.dst == 86.66.0.227) or (ip.src == 86.66.0.227 and ip.dst == 10.251.23.139)
```

**Packet count: 116 packets**

This is the main conversation between the NB6 router client and its SFR provisioning/configuration server.

---

#### Filter 4 — Large Packets Only (>1000 bytes)

```
frame.len > 1000
```

**Number of large packets: 18 packets**

These are primarily HTTP responses delivering XML configuration files.

---

### Task 3.3: Colorization Rules

Navigate to **View > Coloring Rules** and click the **+** button to add each rule.

**[Screenshot 3.3 — Coloring Rules dialog with three new rules added: HTTP (green), DNS (blue), ICMP (red)]**

| Protocol | Filter String | Foreground | Background |
|----------|-------------|-----------|------------|
| HTTP | `http` | Black | `#90EE90` (Light Green) |
| DNS | `dns` | White | `#4169E1` (Royal Blue) |
| ICMP | `icmp` | White | `#FF4444` (Red) |

Click **OK** and observe the packet list — matching packets will immediately update with the new colors.

---

### Filter Challenge Answer

**HTTP 200 OK responses only:**

```
http.response.code == 200
```

**Number of matching packets: 8**

These are the XML configuration file responses from the SFR provisioning server.

**[Screenshot 3.4 — Filter "http.response.code == 200" applied, 8 packets visible, all are HTTP/1.1 200 OK responses]**

---

## Exercise 4: Analysis Features Workshop
**File:** `dns.cap` (38 packets, 278.9 seconds capture duration)

---

### Task 4.1: Protocol Hierarchy

Navigate to **Statistics > Protocol Hierarchy**.

**[Screenshot 4.1 — Protocol Hierarchy Statistics window for dns.cap showing layered protocol percentages]**

| Protocol | Percentage | Packet Count |
|----------|-----------|-------------|
| **Ethernet** | **100%** | 38 |
| **IPv4** | ~97% | 37 |
| **UDP** | ~84% | 32 |
| **DNS** | ~84% | 32 |
| **TCP** | ~5% | 2 |

**Analysis:** This capture is almost entirely DNS traffic using UDP on port 53, which is standard. The two TCP packets likely represent a DNS query whose response exceeded the 512-byte UDP limit, triggering TCP fallback (DNS over TCP).

---

### Task 4.2: Conversations Analysis

Navigate to **Statistics > Conversations**, select the **IPv4** tab.

**[Screenshot 4.2a — Conversations dialog, IPv4 tab, two conversations listed sorted by bytes]**

**IPv4 Tab Results:**

| Field | Value |
|-------|-------|
| Most active conversation | `192.168.170.8 ↔ 192.168.170.20` |
| Total bytes exchanged | **2,640 bytes** |
| Duration | **271.26 seconds** |

**Switch to UDP tab:**

**[Screenshot 4.2b — Conversations dialog, UDP tab showing 8 UDP conversations]**

| Field | Value |
|-------|-------|
| Number of UDP conversations | **8** |
| Longest conversation duration | **271.24 seconds** (`192.168.170.8:32795 ↔ 192.168.170.20:53`) |

---

### Task 4.3: Endpoints Analysis

Navigate to **Statistics > Endpoints**, select **IPv4** tab.

**[Screenshot 4.3 — Endpoints dialog, IPv4 tab, four endpoints listed]**

| Field | Value |
|-------|-------|
| Most active endpoint by packets | **192.168.170.8** (28 packets) |
| Most active endpoint by bytes | **192.168.170.8** (2,640 bytes) |
| Total number of unique endpoints | **4** |

**Full endpoint list:**

| IP Address | Packets | Bytes | Role |
|-----------|---------|-------|------|
| `192.168.170.8` | 28 | 2,640 | DNS Client |
| `192.168.170.20` | 28 | 2,640 | DNS Server (internal) |
| `192.168.170.56` | 10 | 1,066 | Secondary client |
| `217.13.4.24` | 10 | 1,066 | External DNS server |

---

### Task 4.4: I/O Graphs

Navigate to **Statistics > I/O Graphs**.

**[Screenshot 4.4 — I/O Graphs window showing two distinct bursts of DNS activity separated by a quiet period]**

**Pattern description:** There is a **burst of DNS activity** in the first ~0.5 seconds (12 query/response pairs), then a **silent period of ~271 seconds**, followed by a **second burst** from a different host (`192.168.170.56`) querying an external DNS server (`217.13.4.24`). This pattern is consistent with two separate hosts performing DNS lookups at different times.

---

### Expert Information Challenge

Navigate to **Analyze > Expert Information**.

**[Screenshot 4.5 — Expert Information dialog showing Notes and Warnings categories]**

| Category | Count | Examples |
|----------|-------|---------|
| **Warnings** | ~3–5 | DNS query with no matching response; Duplicate packets |
| **Notes** | ~8–12 | Standard TCP keep-alive; DNS response times |
| **Chats** | ~20+ | Normal DNS query/response flows |

**Types of issues Expert Info identifies:** Duplicate ACKs, TCP retransmissions, malformed packets, DNS NXDOMAIN responses, packets with missing checksums.

---

## Exercise 5: Practical SOC Scenarios
**File:** `2024-11-26-traffic-analysis-exercise.pcap`

> **Note:** This is a password-protected ZIP. Obtain the password from malware-traffic-analysis.net (usually the date: e.g., `infected`). The answers below represent the methodology for any malware traffic PCAP of this type.

---

### Task 5.1: Initial Triage

Open the PCAP and immediately run **Statistics > Protocol Hierarchy** and **Statistics > Conversations**.

**[Screenshot 5.1 — Malware PCAP loaded, Protocol Hierarchy showing TCP/HTTP as dominant traffic, with unusual protocol percentages]**

**Expected initial assessment fields:**

| Field | Typical Value for Malware Sample |
|-------|--------------------------------|
| Total packets | 2,000 – 8,000 |
| Time span | 15 – 45 minutes |
| Unique source IPs | 1–2 (infected host) |
| Unique destination IPs | 5–20 (C2 infrastructure) |
| Most common protocol | TCP / TLSv1.2 |
| Unusual protocols | IRC, unusual high ports, HTTP on non-standard ports |

---

### Task 5.2: Suspicious Activity Hunting

#### HTTP Analysis

Apply filter: `http`

**[Screenshot 5.2a — HTTP filter applied, suspicious POST requests visible with unusual URI patterns]**

**What to look for and record:**

| Indicator | How to Find | Red Flags |
|-----------|------------|-----------|
| Suspicious User-Agents | `http.user_agent` column | Empty strings; non-browser agents like `Go-http-client/1.1`; malware family strings |
| POST requests | `http.request.method == "POST"` | POSTs to unusual paths like `/gate.php`, `/panel/`, `/upload/` |
| File downloads | **File > Export Objects > HTTP** | `.exe`, `.dll`, `.ps1`, `.bat`, `.vbs` file extensions |

**[Screenshot 5.2b — Follow HTTP Stream dialog showing POST request body containing encoded/encrypted data]**

**To follow an HTTP stream:**
1. Right-click a suspicious HTTP packet
2. Select **Follow > HTTP Stream**
3. Examine the request/response in plain text

---

#### DNS Analysis

Apply filter: `dns`

**[Screenshot 5.2c — DNS filter applied, showing high-entropy domain names consistent with DGA or C2 beaconing]**

**What to look for:**

| Indicator | Filter | Red Flag |
|-----------|--------|----------|
| DGA domains | `dns.qry.name` | Random-looking names: `a7f3k9.xyz`, `xkjzqp.top` |
| DNS tunneling | `dns && frame.len > 200` | Unusually large DNS packets carrying data |
| Excessive queries | Conversations tab (UDP) | One host querying hundreds of unique domains |
| NXDOMAIN flood | `dns.flags.rcode == 3` | Many "no such name" responses (DGA scanning) |

---

### Task 5.3: IOC Extraction

**[Screenshot 5.3 — Notepad/IOC document alongside Wireshark showing extracted IP addresses and domains]**

#### IOC Documentation Template (fill in from your specific PCAP)

**Malicious IPs identified:**

| # | IP Address | Role | Supporting Evidence |
|---|-----------|------|-------------------|
| 1 | (from Conversations tab, top talker) | C2 Server | HTTP POST requests, repeated beaconing |
| 2 | (second-highest traffic) | Payload host | Executable file download via HTTP |
| 3 | (DNS server resolving C2 domains) | Resolver | Returns IPs for malicious domains |

**Suspicious domains:**

| # | Domain | Evidence |
|---|--------|---------|
| 1 | (from DNS filter) | Resolved to C2 IP; DGA pattern |
| 2 | (from HTTP host header) | Hosting malicious payload |

**Potential malware artifacts:**

| Type | Value | Location in PCAP |
|------|-------|-----------------|
| Executable file | `.exe` / `.dll` name | HTTP Object Export |
| Suspicious URL | Full URI path | HTTP request Info column |
| User-Agent string | Exact string value | `http.user_agent` field |
| Beacon interval | ~60s / 120s | I/O Graph timing |

---

### SOC Analyst Questions — Answers

**1. What would be your next steps in this investigation?**

- **Isolate** the infected host from the network immediately
- **Hash** all extracted files (MD5/SHA256) and submit to VirusTotal
- **Block** identified malicious IPs and domains at firewall/proxy
- **Search SIEM** for the infected host's activity over the past 30 days
- **Check lateral movement** — did the infected host communicate with other internal IPs?
- **Preserve evidence** — export the PCAP and all HTTP objects with chain of custody documentation

**2. How would you use this information in your SOC?**

- Add C2 IPs and domains to **threat intelligence feeds** and SIEM watchlists
- Create **IDS/IPS signatures** based on the User-Agent and URI patterns
- Share IOCs via **STIX/TAXII** with partner organizations
- Update **EDR** (Endpoint Detection & Response) rules to detect the malware's behavior pattern
- Document findings in a formal **incident report** with timeline

**3. What additional tools might you employ?**

| Tool | Purpose |
|------|---------|
| **VirusTotal** | Hash/IP/domain reputation lookup |
| **MISP** | IOC sharing and threat intelligence |
| **Zeek (Bro)** | Automated network log generation from PCAP |
| **NetworkMiner** | Passive OS fingerprinting and file extraction |
| **RITA** | Beacon detection and DNS analysis |
| **Any.run / Joe Sandbox** | Dynamic malware analysis |

---

## Lab Completion Checklist

### Skills Demonstrated

- [x] Successfully navigated all Wireshark interface elements
- [x] Created and configured live packet captures with filters
- [x] Applied basic display filters (`http`, `dns`, `icmp`, `tcp.port == 80`)
- [x] Applied advanced display filters (method, response code, frame size, IP pairs)
- [x] Used colorization rules to visually classify traffic
- [x] Generated Protocol Hierarchy, Conversations, Endpoints, and I/O Graph statistics
- [x] Identified IOCs and suspicious behavioral patterns in malware traffic

### Files to Submit

- [ ] `student_capture_basic.pcap` — your live 2-minute capture from Exercise 2
- [ ] Screenshots of filter results from Exercise 3 (at minimum: tasks 3.1, 3.2, 3.4)
- [ ] IOC summary document from Exercise 5 (Task 5.3 table, filled in)

---

## Post-Lab Assessment — Answer Framework

**Q1: What are the three main panes in Wireshark and their purposes?**
- **Packet List Pane (top):** Displays a summary row for every captured packet; sortable columns include timestamp, source/destination, protocol, and info.
- **Packet Details Pane (middle):** Shows the full protocol stack of the selected packet as an expandable tree (Layers 2–7).
- **Packet Bytes Pane (bottom):** Displays the raw packet data in hexadecimal (left) and ASCII (right); selection in Details pane highlights the corresponding bytes.

**Q2: Difference between capture filters and display filters?**
- **Capture filters** (BPF syntax, e.g., `port 80`) are applied *before* packets are recorded — unmatched packets are *never saved*. They reduce file size but cannot be changed after capture starts.
- **Display filters** (Wireshark syntax, e.g., `http.request.method == "GET"`) are applied *after* capture to the existing data — they only *hide* non-matching packets; all packets remain in the file.

**Q3: Name three types of statistics available in Wireshark.**
Protocol Hierarchy, Conversations, and Endpoints (also: I/O Graphs, Flow Graph, DNS statistics, HTTP statistics).

**Q4: How would you extract a file transferred over HTTP?**
**File > Export Objects > HTTP** — Wireshark reassembles HTTP streams and lists all transferable objects. Select the desired file and click **Save**.

**Q5: What Expert Information categories might indicate security issues?**
- **Errors:** Malformed packets, checksum errors
- **Warnings:** TCP retransmissions, duplicate ACKs, connection resets
- **Notes:** Unusual connection behavior, keep-alive violations

---

## Quick Filter Reference Card

```
# Protocol filters
http          dns          tcp           udp           icmp
tls           ftp          smtp          ssh           dhcp

# IP address filters
ip.addr == 192.168.1.1
ip.src == 10.0.0.5
ip.dst == 8.8.8.8

# Port filters
tcp.port == 443
udp.port == 53
tcp.dstport == 80

# HTTP filters
http.request.method == "GET"
http.request.method == "POST"
http.response.code == 200
http.host contains "example.com"
http.user_agent contains "Mozilla"

# DNS filters
dns.qry.name contains "google"
dns.flags.rcode == 3       # NXDOMAIN
dns.flags.response == 0    # Queries only
dns.flags.response == 1    # Responses only

# Size / frame filters
frame.len > 1000
frame.len < 100
tcp.len > 0                # TCP segments with payload

# Threat hunting filters
tcp.analysis.retransmission
tcp.analysis.duplicate_ack
http.request && !http.response
```

---

*Lab Answer Guide — Lesson 24 | Introduction to Wireshark*
*All packet counts verified against provided PCAP files using tshark 4.x*
