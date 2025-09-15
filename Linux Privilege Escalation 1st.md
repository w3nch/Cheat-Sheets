#linux #previlege-escalation #guide
It means moving from a low-privileged user (like `www-data` or `user`) to a higher one, such as `root`. After gaining a foothold on a Linux machine, you often need root access to read flags, view sensitive files, or fully take over the system. So, in this basic guide, you'll find resources including labs, writeups, and blogs. I'm open to suggestions and improvements in any form.

![I am Root](https://w0.peakpx.com/wallpaper/220/987/HD-wallpaper-groot-i-am-root-ubuntu-linux-terminal-hacker-computer-funny-groot.jpg)
### Core Sections

#### 1. **Enumeration Basics**
What to look for and why:
- Kernel version
    
- SUID/SGID binaries
    
- Writable files/folders
    
- Cron jobs
    
- Services/Processes
    
- Network access
    
- Environment variables
    
- Sudo permissions

### Basic Approach: The 6-Point Checklist

These six things are what you _always_ check when escalating privileges.

---

#### 1. **Check Kernel & OS Info**

Find out the kernel version — maybe it's old and vulnerable.
``` bash
uname -a
cat /proc/version
cat /etc/*release*
```
**Look for:** Known kernel exploits (e.g., Dirty Cow, Dirty Pipe)

---

#### 2. **Check for SUID/SGID Binaries**

SUID gives root-level access to a binary. If it’s misconfigured, you can exploit it.
``` bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
```
**Common misused SUID binaries:** `nmap`, `vim`, `less`, `cp`, `bash`

---
#### 3. **Check for World-Writable or Misowned Files**

You might be able to edit or replace root-owned scripts or services.
``` bash
find / -writable -type f 2>/dev/null
find / -writable -type d 2>/dev/null
```
Also check for:
``` bash
ls -la /etc/passwd
ls -la /etc/shadow
```

---
#### 4. **Check for Running Services & Cron Jobs**

Misconfigured cron jobs are goldmines.
``` bash
ps aux
cat /etc/crontab
ls -la /etc/cron.*
```
Look for scripts run as root that you can modify.

---

#### 5. **Check for Passwords in Files**

Sometimes developers leave secrets behind.
``` bash
grep -Ri "password" /etc/*
grep -R "password" /home/* 2>/dev/null
```
Search `.bash_history`, config files, `.git` repos, or backup files (`.bak`, `~`)

---

#### 6. **Check for Abusable Capabilities**

Linux capabilities let binaries do special things even without being SUID.
``` bash
getcap -r / 2>/dev/null
```
Look for stuff like:
``` bash
cap_setuid+ep
cap_net_bind_service+ep
```


### Useful Tool

These automate a lot of the checks:
- LinPEAS
``` bash
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh && ./linpeas.sh
```

### Learn These Exploits by Name

Know their names and search them by kernel version if needed:

- **Dirty Cow** – CVE-2016-5195
    
- **Dirty Pipe** – CVE-2022-0847
    
- **OverlayFS** – CVE-2021-4034
    
- **Polkit pkexec** – CVE-2021-4034
    
- **Cronjob misconfig**
    
- **Sudo misconfig / sudo without password**

## Common Misconfigurations

|Thing|What to look for|
|---|---|
|`sudo -l`|Run commands as root without password|
|Writable `/etc/passwd`|You can create a new root user manually|
|Custom services|Run as root but editable by you|
|Docker/LXC containers|Breakout possibilities|
### 🛠 Manual Exploit Examples

 1. Sudo abuse
``` bash
sudo -l
sudo /bin/bash   # If allowed
```
2. SUID binary (e.g., Nmap)
``` bash
nmap --interactive
!sh
```
3. Writable `/etc/passwd`
``` bash
openssl passwd "pass123"
# Add new line to /etc/passwd with uid=0
```

###  Labs to Practice

| Platform   | Lab Name                 | Notes                                      |
| ---------- | ------------------------ | ------------------------------------------ |
| TryHackMe  | “Linux PrivEsc”          | Beginner-friendly, step-by-step            |
| HackTheBox | “Beep”, “Lame”, “Bashed” | Realistic Linux privilege escalation paths |
| VulnHub    | “Basic Pentesting 1 & 2” | Classic local privilege escalation targets |
| Suggestion | -                        | -                                          |
### Solid Writeups

- [GTFOBins](https://gtfobins.github.io/) – SUID, sudo, and other abuses
    
- [0xdf’s](https://0xdf.gitlab.io/) HTB Writeups – Very methodical
    
- [HackTricks](https://book.hacktricks.wiki/en/index.html) – Encyclopedic
    
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) – Real use-case examples


---

### Blogs & Guides

- [PEASS-ng](https://github.com/carlospolop/PEASS-ng) – LinPEAS is your best friend
- [Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2)
- [Decline](https://delinea.com/blog/linux-privilege-escalation) Privilege escalation on Linux
- [Vaadata](https://www.vaadata.com/blog/linux-privilege-escalation-techniques-and-security-tips/) Linux Privilege Escalation: Techniques and Security Tips


---

###  Suggested Structure for Each Technique

1. **What is it?**
    
2. **Why does it happen?**
    
3. **How to detect it?**
    
4. **How to exploit it?**
    
5. **Real-world example (link to writeup/lab)**

### Final Tips

- Always **enumerate properly** before launching any exploit.
    
- Keep a local copy of privilege escalation scripts.
    
- Practice on platforms like **Hack The Box**, **TryHackMe**, or **VulnHub**.