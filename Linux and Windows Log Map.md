## `/var/log` — Linux Logs Reference Table

| Log / Path                    | What it Logs                            | Why SOCs Care                                       |
| ----------------------------- | --------------------------------------- | --------------------------------------------------- |
| `/var/log/auth.log`           | SSH logins, sudo, user/password changes | Brute force, lateral movement, privilege escalation |
| `/var/log/secure`             | Same as `auth.log` (RHEL/CentOS)        | Same purpose, different distro                      |
| `/var/log/syslog`             | General system & service messages       | Timeline reconstruction                             |
| `/var/log/messages`           | General system logs (older/RHEL)        | Legacy systems analysis                             |
| `/var/log/kern.log`           | Kernel messages, module loads           | Rootkits, kernel exploits                           |
| `/var/log/boot.log`           | Boot & startup messages                 | Reboots, persistence                                |
| `journalctl`                  | systemd logs (all services)             | Full system timeline                                |
| `/var/log/journal/`           | Persistent journal storage              | Forensics after reboot                              |
| `/var/log/ufw.log`            | Firewall allow/deny events              | Network attacks                                     |
| `/var/log/firewalld`          | Firewall logs (firewalld)               | Network defense                                     |
| `/var/log/apache2/access.log` | HTTP requests                           | Web attacks, webshells                              |
| `/var/log/apache2/error.log`  | Web server errors                       | Exploit failures                                    |
| `/var/log/nginx/access.log`   | HTTP requests                           | Same as Apache                                      |
| `/var/log/nginx/error.log`    | Nginx errors                            | Same as Apache                                      |
| `/var/log/vsftpd.log`         | FTP access                              | Unauthorized file transfer                          |
| `/var/log/mail.log`           | Mail server activity                    | Phishing, exfil                                     |
| `/var/log/cron`               | Cron job executions                     | Persistence                                         |
| `/var/spool/cron/`            | User cron jobs                          | Malware execution                                   |
| `/var/log/wtmp`               | Successful logins (binary)              | Session tracking                                    |
| `/var/log/btmp`               | Failed logins (binary)                  | Brute force detection                               |
| `/var/log/lastlog`            | Last login per user                     | Dormant account abuse                               |
| `/var/log/dpkg.log`           | Package install/remove                  | Tool deployment                                     |
| `/var/log/yum.log`            | Package installs (RHEL)                 | Same as dpkg                                        |
| `/var/log/audit/audit.log`    | Auditd events                           | High-fidelity detection                             |
| `/var/log/fail2ban.log`       | Blocked IPs                             | Attack prevention evidence                          |
| `/var/log/wazuh/`             | Wazuh agent activity                    | EDR detections                                      |
| `/var/log/docker/`            | Container logs                          | Container compromise                                |
| `/var/log/mysql/`             | DB queries & errors                     | Data theft                                          |
| `/var/log/postgresql/`        | DB activity                             | Data exfil                                          |
| `*.1`, `*.gz`                 | Rotated older logs                      | Historical attacker activity                        |

| Priority | Log                   |
| -------- | --------------------- |
| 1        | `auth.log` / `secure` |
| 2        | `journalctl`          |
| 3        | `syslog` / `messages` |
| 4        | Web server logs       |
| 5        | Cron / persistence    |
|  6       | Kernel logs           |
## 🪟 Windows Logs — SOC Reference Table

### Authentication & Access

| Log                | Location                               | What it Logs                                                | Why  Care                                           |
| ------------------ | -------------------------------------- | ----------------------------------------------------------- | --------------------------------------------------- |
| **Security**       | Event Viewer → Windows Logs → Security | Logon/logoff, failed logins, account changes, privilege use | Brute force, lateral movement, privilege escalation |
| Event ID 4624      | Security                               | Successful logon                                            | Who logged in, from where                           |
| Event ID 4625      | Security                               | Failed logon                                                | Brute force detection                               |
| Event ID 4672      | Security                               | Admin privileges assigned                                   | Priv-esc                                            |
| Event ID 4720      | Security                               | User created                                                | Persistence                                         |
| Event ID 4722      | Security                               | User enabled                                                | Backdoor accounts                                   |
| Event ID 4728/4732 | Security                               | User added to group                                         | Privilege abuse                                     |
### System & OS Activity
| Log           | Location                             | What it Logs                             | Why  Care            |
| ------------- | ------------------------------------ | ---------------------------------------- | -------------------- |
| **System**    | Event Viewer → Windows Logs → System | Service start/stop, driver load, reboots | Persistence, crashes |
| Event ID 7045 | System                               | New service installed                    | Malware persistence  |
| Event ID 6005 | System                               | Event log started                        | System boot          |
| Event ID 6006 | System                               | Event log stopped                        | Shutdown             |
| Event ID 7036 | System                               | Service state changed                    | Suspicious services  |

### Application Behavior
| Log             | Location                                  | What it Logs         | Why Care                 |
| --------------- | ----------------------------------------- | -------------------- | ------------------------ |
| **Application** | Event Viewer → Windows Logs → Application | App errors & crashes | Malware failures         |
| Event ID 1000   | Application                               | App crash            | Payload execution issues |
### PowerShell & Script Abuse
| Log            | Location                                                          | What it Logs         | Why  Care          |
| -------------- | ----------------------------------------------------------------- | -------------------- | ------------------ |
| **PowerShell** | Applications and Services Logs → Microsoft → Windows → PowerShell | Script execution     | LOLBins            |
| Event ID 4104  | PowerShell                                                        | Script block logging | Obfuscated malware |
| Event ID 4103  | PowerShell                                                        | Module logging       | Command abuse      |
### Process & Execution
| Event ID | What it Logs        | Why  Care         |
| -------- | ------------------- | ----------------- |
| 1        | Process creation    | Malware execution |
| 3        | Network connections | C2 traffic        |
| 7        | Image loaded (DLLs) | Injection         |
| 8        | CreateRemoteThread  | Process injection |
| 10       | Process access      | Credential theft  |
| 11       | File create         | Dropped payloads  |
| 12–14    | Registry changes    | Persistence       |
Sysmon logs live in:
```bash
Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
```

### Network & Remote Access
| Log                     | What it Logs            | Why  Care        |
| ----------------------- | ----------------------- | ---------------- |
| RDP logs                | Remote Desktop activity | Lateral movement |
| Event ID 4624 (Type 10) | RDP logon               | Remote access    |
| Windows Firewall        | Allowed/blocked traffic | Exfiltration     |
### Defender / Security Tools
| Log                | Location                       | What it Logs      |
| ------------------ | ------------------------------ | ----------------- |
| Microsoft Defender | Applications and Services Logs | Malware detection |
| Event ID 1116      | Malware detected               |                   |
| Event ID 1117      | Malware action taken           |                   |
### Persistence & Scheduled Tasks
| Log            | Event ID | Why                |
| -------------- | -------- | ------------------ |
| Task Scheduler | 106      | New scheduled task |
| Task Scheduler | 140      | Task updated       |
### Installation & Changes
| Log          | Event ID | Why                |
| ------------ | -------- | ------------------ |
| Security     | 4697     | Service installed  |
| MsiInstaller | 11707    | Software installed |

| Priority | Log         |
| -------- | ----------- |
| 1        | Security    |
| 2        | Sysmon      |
| 3        | PowerShell  |
| 4        | System      |
| 5        | Application |
| 6        | Defender    |
