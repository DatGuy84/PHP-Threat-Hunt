# Threat Hunt Report: PHP2Shell — The Hartwell Breach

**Investigation:** Hartwell Medical Group — WordPress Web Server Compromise  
**Investigation Date:** October 23, 2026  
**Environment:** Debian 13, Apache, PHP, WordPress  
**Status:** 18 investigation questions documented; findings based on available telemetry

---

## Platforms and Languages Leveraged

**Platforms**
- Microsoft Defender Advanced Hunting
- Log Analytics Workspace (custom ingested Linux and web telemetry)
- Debian 13 Apache/WordPress server (`192.168.1.120`)

**Languages and Tools**
- **Kusto Query Language (KQL)** — Apache access/error logs, enriched HTTP requests, and Sysmon process creation events
- **Linux utilities** — `ip`, `ss`, `ps`, `grep`, `head`, `curl`, `chmod`, `nohup`, `systemctl`, `crontab`, `base64`
- **MySQL / SQL** — investigation of queries targeting WordPress user records
- **HTTP/PHP** — multipart form uploads, PHP session handling, web shell command execution, custom headers

**Telemetry tables:** `HartwellApache_CL`, `HartwellApacheError_CL`, `HartwellHTTPEnriched_CL`, `HartwellSysmon_CL`. The hunt also referenced security monitoring and service activity; the conclusions below are limited to the evidence documented in the investigation.

> **Time handling:** The hunt window was `2026-10-23 04:00–16:00 UTC`. Queries use `OriginalTime`, the event timestamp, rather than the ingestion timestamp.

---

## Scenario

Hartwell Medical Group's Apache-hosted WordPress server became the target of suspicious HTTP traffic from `192.168.1.100`. The investigation traced reconnaissance activity, a suspected PHP session upload-progress exploitation path, access to a PHP web shell named `health-check.php`, command execution as the low-privilege `www-data` account, WordPress credential access, attempted security-monitoring disruption, and cron-based persistence involving `/dev/shm/.cache-helper`.

The attacker also issued commands to Base64-encode sensitive WordPress configuration and database content. The available evidence supports exfiltration through the existing web shell HTTP response channel; no separate outbound exfiltration connection was identified. Network discovery was observed, but lateral movement to another host was not established.

---

## Key Observations

- **Suspected source:** `192.168.1.100`; the targeted web server was `192.168.1.120`.
- **Reconnaissance:** The Apache `UserAgent` field included an **Nmap Scripting Engine** signature.
- **Exploitation indicators:** PHP session warnings occurred alongside repeated `POST` requests with `multipart/form-data` and `PHPSESSID` cookies. These observations supported the hunt's `session.upload_progress` finding.
- **Web shell:** Requests to `/health-check.php?cmd=...` contained command-execution patterns.
- **Execution context:** Sysmon showed `/usr/sbin/apache2` spawning `/usr/bin/dash` processes as `www-data`.
- **Obfuscated commands:** The custom HTTP header `X-HMG-Debug` carried commands encoded using **ROT13 followed by Base64**.
- **Credential access:** The attacker read `/var/www/html/wp-config.php` and queried `wp_users.user_pass`.
- **Monitoring targets:** `sysmon`, `auditd`, and `SplunkForwarder` were targeted with `systemctl stop` commands. The report concluded the attempts failed due to insufficient `www-data` privileges; process creation logs by themselves show attempts, not service-stop outcomes.
- **Persistence:** A cron entry attempted to execute `/dev/shm/.cache-helper` every five minutes.
- **Data handling:** `wp-config.php` and WordPress user records were passed to `base64`, consistent with returning encoded content through web shell HTTP responses.
- **Lateral movement:** No indication of remote access to another internal system was identified in the documented investigation.

---

## Timeline and KQL Queries Used

The sections below follow the investigative sequence in the original report. Screenshots can be added later using GitHub-hosted attachments or repository-relative paths (for example, `screenshots/01-source-ip.png`).

### 1. Identify the Suspicious Source IP

I began by counting Apache requests per source IP within the investigation window. The unusually high request volume associated with `192.168.1.100` made it a priority for investigation. The report also notes that this IP differed from the known SSH-authorized addresses (`192.168.1.50` and `192.168.1.80`); that comparison provides context, though SSH authorization does not itself establish HTTP authorization.

```kql
let start_date = datetime(2026-10-23T04:00:00Z);
let end_date = datetime(2026-10-23T16:00:00Z);
HartwellApache_CL
| where OriginalTime between (start_date .. end_date)
| summarize RequestCount = count() by SourceIP
| order by RequestCount desc
```


<img width="657" height="322" alt="image" src="https://github.com/user-attachments/assets/5b1801fc-7e7a-494a-865b-d234f375fc59" />

**Flag:** `192.168.1.100` — suspected attacker IP.

### 2. Identify the Reconnaissance Tool

I pivoted to the suspected source and grouped HTTP requests by user agent. The results included a user agent identifying the **Nmap Scripting Engine**, indicating automated reconnaissance.

```kql
let start_date = datetime(2026-10-23T04:00:00Z);
let end_date = datetime(2026-10-23T16:00:00Z);
let badIP = "192.168.1.100";
HartwellApache_CL
| where OriginalTime between (start_date .. end_date)
| where SourceIP == badIP
| summarize Requests = count() by UserAgent
| order by Requests desc
```

<img width="861" height="593" alt="image" src="https://github.com/user-attachments/assets/28f00610-0da3-4f8b-aacf-0d86f36f68e4" />

**Flag:** `Nmap`.

### 3. Investigate PHP Session Warnings

Apache error logs showed three recurring PHP session warnings: invalid session IDs, failures reading session data, and failures writing session data. These warnings prompted closer examination of the HTTP request format.

```kql
let start_date = datetime(2026-10-23T04:00:00Z);
let end_date = datetime(2026-10-23T16:00:00Z);
let badIP = "192.168.1.100";
HartwellApacheError_CL
| where OriginalTime between (start_date .. end_date)
| where ClientIP contains badIP
| where Message contains "PHP Warning"
| distinct Message
```

<img width="855" height="330" alt="image" src="https://github.com/user-attachments/assets/fb735a93-8690-4da9-bdc1-050a7722aff8" />

I then reviewed enriched HTTP requests carrying PHP session information:

```kql
let start_date = datetime(2026-10-23T04:00:00Z);
let end_date = datetime(2026-10-23T16:00:00Z);
let badIP = "192.168.1.100";
HartwellHTTPEnriched_CL
| where OriginalTime between (start_date .. end_date)
| where id_orig_h == badIP
| where request_headers contains "PHP"
| project OriginalTime, id_orig_h, method, uri, request_headers
```

<img width="882" height="601" alt="image" src="https://github.com/user-attachments/assets/3418dbae-4ca0-478b-9158-59039693197d" />

The combination of `PHPSESSID` cookies and multipart submissions suggested abuse of PHP's session upload-progress functionality. This is an investigative inference from the warnings and request characteristics, not something established by the warnings alone.

**Flag:** `session.upload_progress` (hunt finding).

### 4. Confirm the HTTP Method and Content Type

I expanded the enriched HTTP query to expose the content type. The suspicious requests used `POST` with `multipart/form-data`, consistent with the suspected upload-progress exploitation path.

```kql
let start_date = datetime(2026-10-23T04:00:00Z);
let end_date = datetime(2026-10-23T16:00:00Z);
let badIP = "192.168.1.100";
HartwellHTTPEnriched_CL
| where OriginalTime between (start_date .. end_date)
| where id_orig_h == badIP
| where request_headers contains "PHP"
| project OriginalTime, id_orig_h, method, content_type, request_headers
```

**Flag:** `POST, multipart/form-data`.

### 5. Locate the Web Shell

I examined distinct requested URIs from the suspicious source. Requests to `health-check.php` included command parameters such as `cmd=id` and `cmd=whoami`, which are strong indicators of a command-execution web shell.

```kql
let start_date = datetime(2026-10-23T04:00:00Z);
let end_date = datetime(2026-10-23T16:00:00Z);
let badIP = "192.168.1.100";
HartwellApache_CL
| where OriginalTime between (start_date .. end_date)
| where SourceIP == badIP
| where URI != "/"
| summarize arg_min(OriginalTime, *) by URI
| project OriginalTime, SourceIP, URI
```

<img width="877" height="442" alt="image" src="https://github.com/user-attachments/assets/9a2e51dc-e41e-4078-9719-a267ac13540d" />

**Flag:** `health-check.php`.

### 6. Establish the Execution Account and Parent Process

Sysmon process creation telemetry showed command execution under `www-data`, with the Apache process launching a shell. This connected the HTTP activity to execution on the host.

```kql
let start_date = datetime(2026-10-23T04:00:00Z);
let end_date = datetime(2026-10-23T16:00:00Z);
HartwellSysmon_CL
| where OriginalTime between (start_date .. end_date)
| where RuleName == "ProcessCreate"
| where ParentImage contains "apache"
| project OriginalTime, ParentImage, Image, CommandLine, User
```

**Observed process chain:**

```text
/usr/sbin/apache2 (www-data)
    └── /usr/bin/dash
          ├── /usr/bin/id
          └── /usr/bin/whoami
```

**Flag:** `www-data`.

### 7. Investigate the Obfuscated Command Header

The enriched HTTP logs exposed a custom header, `X-HMG-Debug`, and decoded command content. The attacker used the header to pass commands to the web shell rather than relying only on URL query parameters.

```kql
let start_date = datetime(2026-10-23T04:00:00Z);
let end_date = datetime(2026-10-23T16:00:00Z);
let badIP = "192.168.1.100";
HartwellHTTPEnriched_CL
| where OriginalTime between (start_date .. end_date)
| where id_orig_h == badIP
| where isnotempty(x_hmg_debug_decoded)
| project request_headers, x_hmg_debug_decoded, x_hmg_debug_raw
```

**Flag:** `X-HMG-Debug`.

### 8. Identify the Two Encoding Methods

After identifying the custom `X-HMG-Debug` header, I compared the raw header values with the decoded commands in `HartwellHTTPEnriched_CL`. The values used two layers of obfuscation: **ROT13 first, then Base64**. The receiver reverses the process by decoding Base64 and applying ROT13. These are encoding methods, not encryption.

```kql
let start_date = datetime(2026-10-23T04:00:00Z);
let end_date = datetime(2026-10-23T16:00:00Z);
let badIP = "192.168.1.100";
HartwellHTTPEnriched_CL
| where OriginalTime between (start_date .. end_date)
| where id_orig_h == badIP
| where isnotempty(x_hmg_debug_raw)
| project OriginalTime, x_hmg_debug_raw, x_hmg_debug_decoded, request_headers
```

**Flag:** `rot13, base64`.

### 9. Map the Local Network

I reviewed commands issued as `www-data` to identify the attacker's host-discovery behavior.

```kql
let start_date = datetime(2026-10-23T04:00:00Z);
let end_date = datetime(2026-10-23T16:00:00Z);
HartwellSysmon_CL
| where OriginalTime between (start_date .. end_date)
| where User contains "www-data"
| where isnotempty(CommandLine)
| project User, CommandLine
```

| Command | Purpose |
| --- | --- |
| `ip addr show` | Identify local interfaces and IP addresses |
| `ip neigh` | Inspect the neighbor cache for nearby hosts |
| `ss -tlnp` | Identify listening TCP ports and associated processes |

**Flag:** `ss -tlnp, ip addr show, ip neigh`. These commands demonstrate network reconnaissance, not lateral movement.

### 10. Identify Security Monitoring

The attacker checked installed packages, running processes, files, and services associated with host monitoring. The tools investigated included Sysmon, Linux auditd, and Splunk's forwarder.

```kql
HartwellSysmon_CL
| where RuleName == "ProcessCreate"
| where User == "www-data"
| where CommandLine contains "sysmon"
    or CommandLine contains "splunk"
    or CommandLine contains "auditd"
| project OriginalTime, User, CommandLine, Image, ParentImage
| order by OriginalTime asc
```

**Flag:** `sysmon`, `auditd`, `SplunkForwarder`.

### 11. Locate WordPress Database Credentials

The attacker used file-reading and search commands against the WordPress configuration file, including searches for database and authentication settings.

```kql
let start_date = datetime(2026-10-23T04:00:00Z);
let end_date = datetime(2026-10-23T16:00:00Z);
HartwellSysmon_CL
| where OriginalTime between (start_date .. end_date)
| where User contains "www-data"
| where CommandLine contains "cat"
    or CommandLine contains "head"
    or CommandLine contains "grep"
| project User, RuleName, CommandLine
```

**Flag:** `/var/www/html/wp-config.php` — WordPress configuration file containing database connection settings.

### 12. Identify the Database Table and Password-Hash Column

Sysmon command lines showed SQL `SELECT` statements targeting WordPress user records, including `user_login` and `user_pass`.

```kql
let start_date = datetime(2026-10-23T04:00:00Z);
let end_date = datetime(2026-10-23T16:00:00Z);
HartwellSysmon_CL
| where OriginalTime between (start_date .. end_date)
| where User contains "www-data"
| where CommandLine contains "SELECT"
| project User, RuleName, CommandLine
```

Example query observed in the command lines:

```sql
SELECT user_login, user_pass FROM wp_users;
```

**Flag:** `wp_users, user_pass`. The `user_pass` field contains password hashes rather than plaintext passwords; slow, salted hashing increases the cost of password guessing.

> **Credential handling:** Actual database passwords that appeared in command-line telemetry are intentionally omitted from this public-facing README.

### 13. Identify Monitoring Services Targeted for Shutdown

The attacker issued `systemctl stop` commands against three monitoring services:

```kql
let start_date = datetime(2026-10-23T04:00:00Z);
let end_date = datetime(2026-10-23T16:00:00Z);
HartwellSysmon_CL
| where OriginalTime between (start_date .. end_date)
| where User contains "www-data"
| where CommandLine contains "systemctl"
| project User, RuleName, CommandLine
```

```bash
systemctl stop sysmon
systemctl stop auditd
systemctl stop SplunkForwarder
```

**Flag 13:** `sysmon, auditd, SplunkForwarder` — the three services targeted with `systemctl stop`.

### 14. Determine Whether Monitoring Evasion Succeeded

The next question asked whether any of the monitoring services were successfully disabled and what prevented or allowed the evasion. The investigation identified the commands as running under the low-privilege `www-data` account.

**Question:** Did the attacker successfully disable any of the monitoring services? Explain what prevented or allowed the evasion.

**Flag 14 (my submitted answer):** No the attacker failed to disable Sysmon, auditd and SplunkForwarder because the www-data account does not have root privileges that would be required to stop system-level services.

*Evidence note:* The Sysmon process creation records show the stop attempts and their execution context; the reported failure is the investigation’s assessment rather than a directly captured service exit status.

### 15. Identify the Persistence Mechanism

I searched process command lines for recurring execution mechanisms, including cron and service management. A command attempted to add a cron entry for a hidden executable.

```kql
let start_date = datetime(2026-10-23T04:00:00Z);
let end_date = datetime(2026-10-23T16:00:00Z);
HartwellSysmon_CL
| where OriginalTime between (start_date .. end_date)
| where User contains "www-data"
| where CommandLine contains "systemctl"
    or CommandLine contains "cron"
    or CommandLine contains "systemd"
| project User, RuleName, CommandLine
```

Suspicious scheduled command:

```cron
*/5 * * * * /dev/shm/.cache-helper
```

**Flag:** **Cron / crontab persistence**, configured to run every five minutes. The process creation log establishes the installation attempt; crontab contents or repeated execution would establish persistence success.

### 16. Trace Implant Staging

I searched for commands associated with downloading, preparing, and launching files. The attacker attempted to retrieve content from a localhost HTTP endpoint and save it in shared memory.

```kql
let start_date = datetime(2026-10-23T04:00:00Z);
let end_date = datetime(2026-10-23T16:00:00Z);
HartwellSysmon_CL
| where OriginalTime between (start_date .. end_date)
| where User contains "www-data"
| where CommandLine has_any ("curl", "wget", "chmod", "nohup", "crontab")
| project User, RuleName, CommandLine
```

Relevant command:

```bash
curl -s -o /dev/shm/.cache-helper http://127.0.0.1:8085/update
```

Subsequent commands attempted to make `.cache-helper` executable and run it using `nohup`.

**Flag:** `/dev/shm/.cache-helper`. `/dev/shm` is commonly backed by tmpfs, meaning its contents are volatile and generally lost on reboot. This can complicate disk-based forensic recovery compared with disk-backed temporary directories. `127.0.0.1:8085` refers to a service on the compromised host itself, **not** an identified external attacker IP.

### 17. Assess Data Exfiltration

The attacker issued commands to Base64-encode the WordPress configuration and database records:

```bash
base64 /var/www/html/wp-config.php
```

```bash
mysql -u wpuser wordpress -e "SELECT * FROM wp_users" | base64
```

The second command above is a **sanitized illustration** of the observed query pattern; the original telemetry included additional authentication arguments. The report concluded that the encoded output was returned through the existing web shell HTTP response channel, rather than through a separate outbound connection.

**Question:** How did the attacker exfiltrate stolen data (`wp-config.php` contents and database records) from the server? Describe the method.

**Flag 17 (my submitted answer):** The attacker exfiltrated stolen data from the server by base64 encoding wp-config.php and the WordPress database records, then returning them through the web shell's HTTP responses to the attacker.

The process logs establish encoding commands; HTTP response content would provide the strongest direct confirmation of what was received.

### 18. Assess Lateral Movement

The attacker investigated the network using `ip addr show`, `ip neigh`, and `ss -tlnp`. However, the documented investigation did not identify SSH or other remote-access attempts, remote credential reuse, or tool transfers to other internal systems.

A follow-up hunt for outbound network activity could begin with:

```kql
HartwellSysmon_CL
| where RuleName == "NetworkConnect"
| project OriginalTime, User, Image, CommandLine
| order by OriginalTime asc
```

> The query above is a **recommended follow-up**, not a query shown in the original PDF. Destination-address fields should be inspected and included if available in the event schema.

**Question:** A colleague suggests the attacker may have moved laterally to other systems on the 192.168.1.0/24 network. Examine the available evidence. Is there any indication of lateral movement from the compromised host?

**Flag 18 (my submitted answer):** No, the logs show network reconnaissance but no evidence of outbound connections to other internal hosts, credential use or lateral movement.

This is a visibility-limited conclusion, not proof that movement was impossible.

---

## Summary of Flags

| # | Investigation question | Flag / assessment |
| --- | --- | --- |
| 1 | Suspicious source IP | `192.168.1.100` |
| 2 | Reconnaissance tool | `Nmap` |
| 3 | Exploited PHP feature | `session.upload_progress` (inferred from session and HTTP indicators) |
| 4 | HTTP method and content type | `POST`, `multipart/form-data` |
| 5 | Web shell | `health-check.php` |
| 6 | Web shell execution account | `www-data` |
| 7 | Custom command header | `X-HMG-Debug` |
| 8 | Encoding sequence | ROT13 → Base64 |
| 9 | Network discovery commands | `ss -tlnp`, `ip addr show`, `ip neigh` |
| 10 | Monitoring components identified | Sysmon, Splunk, auditd |
| 11 | WordPress configuration file | `wp-config.php` |
| 12 | User table / password-hash column | `wp_users`, `user_pass` |
| 13 | Services targeted for stopping | `sysmon`, `auditd`, `SplunkForwarder` |
| 14 | Monitoring evasion outcome | No; `www-data` lacked root privileges required to stop system-level services |
| 15 | Persistence mechanism | `crontab` / cron job |
| 16 | Implant staging path | `/dev/shm/.cache-helper` |
| 17 | Exfiltration method | Base64-encoded `wp-config.php` and WordPress database records returned through web shell HTTP responses |
| 18 | Lateral movement | No; network reconnaissance observed, but no evidence of outbound internal connections, credential use, or lateral movement |

---

## Recommended Response Actions

These are **recommendations**, not actions documented as completed in the hunt.

1. **Contain the web server:** Restrict access to the affected Apache/WordPress host and block or investigate the suspicious source IP as appropriate to the environment.
2. **Preserve volatile evidence:** Capture memory, `/dev/shm` contents, running processes, cron entries, and service state before rebooting or removing artifacts.
3. **Remove attacker access:** Investigate and remove `health-check.php`, malicious cron entries, and `.cache-helper` only after evidence preservation and scope validation.
4. **Rotate exposed credentials:** Reset WordPress database credentials and relevant user passwords; review WordPress salts and other secrets in `wp-config.php`.
5. **Investigate monitoring health:** Verify Sysmon, auditd, and Splunk forwarder status, collection gaps, and any attempted audit-rule changes.
6. **Scope the intrusion:** Review HTTP response bodies where available, outbound connection telemetry, neighboring systems, and authentication logs for exfiltration and lateral movement.
7. **Harden the application:** Review PHP session/upload settings, patch the affected software, reduce web-service privileges, and alert on unusual web-server child processes.

---

## Diamond Model of Intrusion Analysis

| Feature | Description |
| --- | --- |
| **Adversary** | Unattributed actor operating from suspected source `192.168.1.100`; no named threat group established. |
| **Capability** | Nmap reconnaissance; suspected PHP session upload-progress exploitation; PHP web shell; ROT13/Base64 command obfuscation; SQL queries; attempted service stopping; cron persistence. |
| **Infrastructure** | Targeted HTTP service on `192.168.1.120`; local endpoint `127.0.0.1:8085/update` observed in a staging command; implant path `/dev/shm/.cache-helper`. |
| **Victim** | Hartwell Medical Group's Debian 13 Apache/WordPress web server, with attacker commands executed as `www-data`. |

```text
                   +-----------------------------+
                   |       Infrastructure        |
                   |  192.168.1.100 -> .120 HTTP |
                   |  localhost:8085 staging     |
                   +--------------+--------------+
                                  |
                                  v
+--------------------+   +--------+---------+   +--------------------+
|     Adversary      |<->|    Capability    |<->|       Victim       |
| Unattributed actor |   | PHP web shell,   |   | Hartwell Medical   |
|                    |   | obfuscation,     |   | Group WordPress    |
|                    |   | cron persistence |   | server (www-data)  |
+--------------------+   +------------------+   +--------------------+
```

---

## Lessons Learned

- **Correlate HTTP and host telemetry.** Apache access/error logs revealed the entry path, while Sysmon connected requests to process execution under `www-data`.
- **Treat suspicious headers as potential command channels.** The `X-HMG-Debug` field illustrates why URL-only inspection can miss web shell activity.
- **Distinguish execution attempts from confirmed outcomes.** `systemctl stop` and `crontab` command lines show attacker intent; service-state and scheduled-execution evidence determine success.
- **Protect application secrets.** Access to `wp-config.php` can expose database credentials, and the `wp_users` table provides password hashes for offline guessing.
- **Preserve volatile artifacts early.** Memory-backed locations such as `/dev/shm` can lose evidence on reboot.
- **Avoid overclaiming scope.** Network discovery is not the same as lateral movement, and a lack of observed movement is not proof of absence.

---

**Report:** PHP2Shell — The Hartwell Breach  
**Scope:** 18 documented findings across reconnaissance, exploitation, execution, discovery, credential access, defense evasion, persistence, and impact assessment  
**Assessment:** Compromise of the WordPress server with command execution and sensitive-data exposure; no lateral movement demonstrated in the documented evidence.
