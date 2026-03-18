# Lesson 26 - Threat Hunting Endpoints - Fully Guided Answers

## English Instructor Guide

> Based on the uploaded lesson worksheet and instructor answer notes. The source files describe expected findings, but they do not include verified live BOTSv3 result values. For that reason, this guide provides accurate guided answers and investigation logic instead of inventing environment-specific counts or account names.

> **Screenshot note:** all screenshots in this guide are clearly labeled illustrative examples. They are training visuals, not real captures from a live BOTSv3 Splunk session.

## How to use this guide

- Run the query shown for each exercise.
- Compare the returned results to the explanation in the guided answer.
- Fill the student workbook using the answer language in the **Workbook-ready answer** section.
- Pivot into surrounding events whenever the answer says **investigate further**.


## Lab Environment Setup

**Objective:** Set up the BOTSv3 practice environment and confirm that students can open Splunk Search & Reporting.

### Guided steps

1. Clone the automated BOTSv3 lab repository.

2. Load the environment variables.

3. Start the Docker environment and wait for Splunk and the dataset to finish loading.

4. Open the Splunk URL provided by the instructor and verify that the Search & Reporting app is available.


### Query or commands

**Setup commands**

```spl
git clone https://github.com/d3vzer0/splunk-bots-docker.git
cd splunk-bots-docker
source deploy.sh all
docker-compose up -d
```

### Guided answer

- Students should confirm that the environment loads without errors and that the BOTSv3 dataset is searchable before beginning any hunting task.

- If the environment is slow at startup, wait for indexing to finish; otherwise, searches may appear incomplete.

- A good validation check is to run a small search first, such as `index=botsv3 | head 10`, before moving into the lab exercises.


### Workbook-ready answer

- **Dataset:** Boss of the SOC version 3 (BOTSv3)

- **Platform:** Splunk Search & Reporting

- **Validation:** Students can search the `botsv3` index and return events


## Exercise 1A - Basic Authentication Event Analysis

**Objective:** Review successful and failed Windows logons and learn how to interpret logon types before hunting for attack patterns.


### Query or commands

**Student query**

```spl
index=botsv3 sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)
| head 100
| table _time, EventCode, User, Logon_Type, Source_Network_Address, ComputerName
```

### What students should notice

- Event ID 4624 means successful logon; Event ID 4625 means failed logon.

- Logon Type 3 (network) is commonly the most frequent because it covers file shares, service access, and other remote resource use.

- Logon Type 2 usually indicates an interactive local logon, while Logon Type 10 usually indicates RDP or other remote interactive access.

- A mix of normal user accounts and service accounts is expected.

### Guided answer

- Students should report that successful logons normally outnumber failed logons in the first sample.

- The most common logon type is usually Type 3 because Windows constantly performs network authentication in the background.

- Frequently appearing accounts are often service accounts plus a small set of active users and administrative accounts.

- At this stage, failed logons alone are not enough to declare an incident. The correct answer is that this search is a baseline view used to understand normal vs suspicious authentication activity.


**Why it matters:** This exercise teaches students not to overreact to single failed logons. Threat hunting starts by understanding what normal activity looks like in the environment.


### Workbook-ready answer

- **Successful logons (4624):** Present throughout the results; typically more common than 4625

- **Failed logons (4625):** Present in smaller clusters; repeated failures require follow-up

- **Most common Logon_Type:** Usually 3 (Network)

- **Frequently appearing accounts:** Service accounts, active users, and occasional admin accounts


### Screenshot

![Exercise 1A - Basic Authentication Event Analysis](screenshots/01_ex1a_authentication_overview.png)


## Exercise 1B - Failed Authentication Pattern Detection

**Objective:** Detect repeated failed logons and decide whether the pattern looks more like brute force, password spraying, or a benign operational issue.


### Query or commands

**Student query**

```spl
index=botsv3 sourcetype="WinEventLog:Security" EventCode=4625
| stats count by User, Source_Network_Address
| where count > 10
| sort -count
```

### What students should notice

- Rows with more than 10 failures are the first candidates for investigation.

- One source repeatedly targeting one account suggests brute force.

- One source touching many accounts with lower counts each suggests password spraying.

- A service account can also produce repeated failures if a password changed but a service or scheduled task was not updated.

### Guided answer

- Students should identify the accounts with the highest failed counts and record the source IP address associated with them.

- The correct interpretation depends on the shape of the results: a single account with many attempts from one address is closer to brute force; multiple accounts from the same address is closer to password spraying.

- Not every repeated failure is malicious. A good answer mentions false positives such as expired passwords, disabled accounts, or misconfigured services.

- The correct next pivot is to review surrounding 4624 events, source IP history, and whether the source is expected for that user or service.


**Why it matters:** This is the first true hunting step. Students move from simple visibility to pattern recognition and must explain why the pattern is suspicious.


### Workbook-ready answer

- **Account with most failures:** The highest-count user returned by the search

- **Number of failed attempts:** Any value above 10 is suspicious enough to review

- **Source IP address:** The repeated source tied to those failures

- **Attack type:** Brute force if one account is heavily targeted; password spray if many accounts are touched


### Screenshot

![Exercise 1B - Failed Authentication Pattern Detection](screenshots/02_ex1b_failed_auth.png)


## Exercise 1C - Successful Authentication After Failures

**Objective:** Correlate failed and successful logons in the same time window to identify possible credential compromise.


### Query or commands

**Student query**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Security" (EventCode=4624 OR EventCode=4625)
| transaction Account_Name maxspan=1h
| where eventcount > 1
| eval failed_attempts=mvcount(mvfilter(EventCode==4625))
| eval successful_logons=mvcount(mvfilter(EventCode==4624))
| where failed_attempts > 5 AND successful_logons > 0
| table Account_Name, failed_attempts, successful_logons, duration
```

### What students should notice

- Any account with more than five failures followed by one or more successes in the same one-hour transaction should be reviewed carefully.

- A result can indicate a successful password attack, but it can also reflect a legitimate user eventually typing the correct password.

- Source address, logon type, host, and time of day are essential for deciding whether the activity is suspicious.

### Guided answer

- Students should report that the key pattern is repeated failures followed by a success for the same account.

- The correct security implication is possible credential compromise, not guaranteed compromise. The event sequence creates a strong lead for investigation rather than final proof.

- A good answer states that the next step is to pivot into the source address, the destination system, any privilege grants, and any later process execution by the same account.


**Why it matters:** This exercise teaches temporal correlation. Many real investigations begin with a suspicious sequence rather than a single alert.


### Workbook-ready answer

- **Accounts with successful attacks:** Any account returned by the query

- **Pattern observed:** Multiple failed logons followed by at least one successful logon

- **Security implications:** Possible successful credential attack; requires validation with host and account context


### Screenshot

![Exercise 1C - Successful Authentication After Failures](screenshots/03_ex1c_fail_then_success.png)


## Exercise 2A - Special Privileges Assignment Analysis

**Objective:** Review Event ID 4672 to determine whether sensitive privileges were assigned to a normal admin, a service account, or a potentially compromised user.


### Query or commands

**Student query**

```spl
index=botsv3 sourcetype="WinEventLog:Security" EventCode=4672
| table _time, User, Privileges, ComputerName
| sort _time
```

### What students should notice

- SeDebugPrivilege is especially high risk because it can be used to access other processes.

- SeBackupPrivilege and SeTakeOwnershipPrivilege are also powerful and should be explained if they appear.

- Service accounts may legitimately receive privileges, so students must note account type and host role.

### Guided answer

- Students should identify any user account, especially a normal interactive user, that receives SeDebugPrivilege or another high-risk privilege.

- A strong answer distinguishes expected service behavior from suspicious interactive behavior. For example, a backup service receiving SeBackupPrivilege can be normal, while a standard user receiving SeDebugPrivilege is more concerning.

- The correct interpretation is not simply '4672 equals malicious.' The answer must connect privilege type, account context, and later activity.


**Why it matters:** Privilege escalation rarely matters in isolation. Its value comes from what happens immediately after the privilege grant.


### Workbook-ready answer

- **Unusual privilege assignments:** Any unexpected grant such as SeDebugPrivilege on a user workstation

- **Affected accounts:** User or service accounts returned in the results

- **Privilege types:** Record the exact privileges and explain why they matter


### Screenshot

![Exercise 2A - Special Privileges Assignment Analysis](screenshots/04_ex2a_privileges.png)


## Exercise 2B - Process Creation with Elevated Privileges

**Objective:** Correlate 4672 and 4688 events to see whether a privileged account immediately launches a shell or admin tool.


### Query or commands

**Student query**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Security" (EventCode=4672 OR EventCode=4688)
| transaction Subject_Account_Name maxspan=5m
| where match(Privileges, ".*SeDebugPrivilege.*") OR match(New_Process_Name, ".*cmd.exe.*|.*powershell.exe.*")
| table _time, Subject_Account_Name, Privileges, New_Process_Name, Process_Command_Line
```

### What students should notice

- PowerShell and cmd.exe are not automatically malicious, but they become more suspicious immediately after a sensitive privilege grant.

- Encoded or obfuscated command lines should be called out explicitly.

- The shorter the time gap between the privilege event and the process creation event, the stronger the investigative lead.

### Guided answer

- Students should report which account received elevated privileges and what process it launched next.

- The strongest answer names the risky process, quotes the suspicious command line, and explains why the combination raises the risk score.

- A correct investigation note states that PowerShell, cmd.exe, net.exe, wmic.exe, or other admin tools are especially important when they appear just after SeDebugPrivilege or related grants.


**Why it matters:** This is where students begin to see post-compromise behavior rather than simple access events.


### Workbook-ready answer

- **Account:** The account shown in the correlated transaction

- **Privileges gained:** Record the high-risk privilege or privileges

- **Processes executed:** List the process name and target host

- **Suspicious commands:** Note any encoded, hidden, scripted, or reconnaissance-style command lines


### Screenshot

![Exercise 2B - Process Creation with Elevated Privileges](screenshots/05_ex2b_process_after_priv.png)


## Exercise 3A - Network Logon Pattern Analysis

**Objective:** Use successful Type 3 network logons to identify remote access paths between systems and possible lateral movement.


### Query or commands

**Student query**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Security" EventCode=4624 Logon_Type=3
| eval src_dest_pair=Source_Network_Address + " -> " + Computer_Name
| stats count by Account_Name, src_dest_pair
| where count > 1
| sort -count
```

### What students should notice

- Repeated workstation-to-workstation or user-to-server movement can be suspicious depending on the role of the account.

- Service accounts often reach several systems legitimately, so students should not flag them automatically.

- The same account authenticating to multiple endpoints in a short period can suggest pivoting or scripted movement.

### Guided answer

- Students should record the accounts that appear across multiple source-to-destination pairs and explain whether the pattern looks normal for the account's function.

- A strong answer points out that user accounts moving laterally between many hosts deserve more attention than a known service account that regularly touches backup or file servers.

- The next pivot is to review process creation, remote service use, and timing around each destination system.


**Why it matters:** Lateral movement is usually identified by a chain of ordinary-looking events. Correlation across hosts is what turns them into a suspicious story.


### Workbook-ready answer

- **Accounts moving laterally:** Accounts with repeated cross-system Type 3 logons

- **Systems involved:** The source and destination systems in the pair

- **Movement patterns:** Repeated remote access, workstation-to-workstation access, or broad host coverage


### Screenshot

![Exercise 3A - Network Logon Pattern Analysis](screenshots/06_ex3a_network_logons.png)


## Exercise 3B - Cross-System Process Execution

**Objective:** Connect remote authentication with process creation to see whether an account authenticated to a system and then executed tools there.


### Query or commands

**Student query**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Security" (EventCode=4624 Logon_Type=3) OR (EventCode=4688)
| transaction Account_Name maxspan=10m
| where eventcount > 1
| eval has_network_logon=if(match(EventCode, "4624"), 1, 0)
| eval has_process_creation=if(match(EventCode, "4688"), 1, 0)
| where has_network_logon=1 AND has_process_creation=1
| table _time, Account_Name, Computer_Name, New_Process_Name, Source_Network_Address
```

### What students should notice

- A remote logon followed by PowerShell, wmic.exe, sc.exe, net.exe, or cmd.exe is more suspicious than a standard application process.

- This search is stronger when the source address is not a known admin workstation.

- Students should note whether the account is performing routine administration or something closer to attacker tooling.

### Guided answer

- Students should report which account authenticated remotely and then launched a process on the destination system.

- The best answer mentions both the host and the process, then explains whether that process suggests shell access, service control, WMI-based activity, or normal administration.

- The correct conclusion is that this pattern can support lateral movement but still requires context before calling it malicious.


**Why it matters:** This is the bridge between access and action. Many lateral movement techniques produce exactly this pattern.


### Workbook-ready answer

- **Remote execution evidence:** Remote logon and process creation tied to the same account within the transaction window

- **Processes executed remotely:** Record the exact process names

- **Attack progression:** Remote access followed by administrative or shell execution on another endpoint


### Screenshot

![Exercise 3B - Cross-System Process Execution](screenshots/07_ex3b_remote_processes.png)


## Exercise 4A - Scheduled Task Creation Analysis

**Objective:** Review scheduled task creation events for signs of persistence, script execution, or suspicious naming.


### Query or commands

**Student query**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Security" EventCode=4698
| table _time, Subject_Account_Name, Task_Name, Task_Content, Computer_Name
| sort _time
```

### What students should notice

- Tasks that run PowerShell, cmd, a script, or downloaded content are higher risk than simple maintenance tasks.

- Very short names, temporary-sounding names, and off-hours creation times are good investigative clues.

- Students should always read task content, not just the task name.

### Guided answer

- Students should identify any task whose content suggests script execution, hidden command execution, or regular startup/logon persistence.

- A strong answer explains who created the task, where it was created, and why the task content looks suspicious.

- The correct interpretation is that task creation can indicate persistence, but the analyst must confirm whether it belongs to legitimate IT administration or attacker follow-on activity.


**Why it matters:** Scheduled tasks are a common persistence mechanism because they are easy to create and blend into normal administration.


### Workbook-ready answer

- **Tasks created:** List the task names returned by the query

- **Created by:** The account that created each task

- **Task purpose:** Describe whether the content looks like maintenance or persistence

- **Persistence indicators:** Script execution, startup or logon trigger, hidden commands, or network retrieval


### Screenshot

![Exercise 4A - Scheduled Task Creation Analysis](screenshots/08_ex4a_tasks.png)


## Exercise 4B - Service Installation Detection

**Objective:** Review new service installations and decide whether the service path, name, and installer context look benign or suspicious.


### Query or commands

**Student query**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Security" EventCode=4697
| table _time, Subject_Account_Name, Service_Name, Service_File_Name, Computer_Name
| sort _time
```

### What students should notice

- Services installed from temporary folders, user profile folders, or downloads folders are highly suspicious.

- Short cryptic service names or fake system-like names deserve attention.

- Students should separate legitimate installer activity from services dropped directly by a user account.

### Guided answer

- Students should record any service installed from a non-standard path and explain why the path is risky.

- A high-quality answer also comments on whether the installing account is expected to perform software deployment.

- The correct security interpretation is possible persistence or defense evasion when a service is created from an unusual location or by an unexpected account.


**Why it matters:** Services provide durable persistence and can also be used for remote execution. Their installation path often reveals the difference between software management and attacker activity.


### Workbook-ready answer

- **New services:** The services returned by the query

- **Installed by:** The account associated with service creation

- **Service locations:** The full executable or DLL path

- **Suspicious indicators:** User-writable directory, temporary path, cryptic name, or fake Microsoft-style name


### Screenshot

![Exercise 4B - Service Installation Detection](screenshots/09_ex4b_services.png)


## Exercise 5A - Complete Attack Chain Reconstruction

**Objective:** Correlate authentication, privilege, execution, and persistence events into a single attack narrative.


### Query or commands

**Query 1**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Security"
(EventCode=4625) OR (EventCode=4624) OR (EventCode=4672) OR (EventCode=4688) OR (EventCode=4698) OR (EventCode=4697)
| transaction Account_Name maxspan=1h
| where eventcount > 5
| eval attack_stages=mvjoin(EventCode, " -> ")
| table _time, Account_Name, attack_stages, Computer_Name, duration
| sort -eventcount
```

**Query 2**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Security"
(EventCode=4625) OR (EventCode=4624) OR (EventCode=4672) OR (EventCode=4688) OR (EventCode=4698) OR (EventCode=4697)
| transaction Account_Name maxspan=2h
| where eventcount > 3
| eval failed_logons=mvcount(mvfilter(EventCode==4625))
| eval successful_logons=mvcount(mvfilter(EventCode==4624))
| eval privilege_grants=mvcount(mvfilter(EventCode==4672))
| eval processes_created=mvcount(mvfilter(EventCode==4688))
| eval tasks_created=mvcount(mvfilter(EventCode==4698))
| eval services_installed=mvcount(mvfilter(EventCode==4697))
| table Account_Name, failed_logons, successful_logons, privilege_grants, processes_created, tasks_created, services_installed, duration
| where failed_logons > 0 AND successful_logons > 0
```

### What students should notice

- Students should look for an account that shows multiple failed logons, at least one success, privilege activity, process execution, and persistence-related events within the same broad time window.

- The result is strongest when the same account and destination hosts appear across several of the earlier exercises.

- A complete attack chain should be narrated in plain language, not only listed as event codes.

### Guided answer

- Students should summarize the attack as a progression: failed logons, successful authentication, privilege escalation, process execution, possible lateral movement, and persistence creation.

- The correct answer is not only the count of each event type. Students must explain what happened first, what happened next, and what evidence supports each stage.

- A strong final answer also maps the findings to MITRE ATT&CK: T1110 Brute Force, T1078 Valid Accounts, T1068 or privilege escalation-related activity, T1021 Remote Services, T1053 Scheduled Task/Job, and T1543 Create or Modify System Process.


**Why it matters:** This is the capstone hunt. The student proves that they can build a defensible attack narrative from several weak signals.


### Workbook-ready answer

- **Primary attack account:** The account with the most complete suspicious event progression

- **Initial access:** Repeated failures followed by success

- **Privilege escalation:** Sensitive privilege grants and related behavior

- **Lateral movement:** Remote logons and remote execution on additional hosts

- **Persistence:** Scheduled task or service creation

- **MITRE ATT&CK mapping:** T1110, T1078, T1021, T1053, T1543, plus privilege escalation activity as applicable


### Screenshot

![Exercise 5A - Complete Attack Chain Reconstruction](screenshots/10_ex5_attack_chain.png)


## Quick reference

| Item | Meaning |
|---|---|

| 4624 | Successful logon |

| 4625 | Failed logon |

| 4672 | Special privileges assigned |

| 4688 | Process creation |

| 4698 | Scheduled task created |

| 4697 | Service installed |

| Logon Type 2 | Interactive local console logon |

| Logon Type 3 | Network logon |

| Logon Type 10 | Remote interactive / RDP |


## Final analyst reminder

A correct threat hunting answer does **not** claim compromise unless the evidence supports it. The strongest student answers use wording such as **possible credential attack**, **requires host validation**, **likely service account behavior**, or **persistence indicator that needs confirmation**.
