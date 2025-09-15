#zeek #network

### **Verify Installation**
```json
zeek --version
zeekctl --version
which zeek
```

### **Running Zeek on PCAP**
```json
zeek -r sample.pcap
zeek -r sample.pcap local.zeek
ls *.log
```
**Important logs:**
- **conn.log** — connections, IPs, ports, protocols
- **http.log** — HTTP requests/responses
- **dns.log** — DNS queries/responses
- **files.log** — metadata of observed files
- **notice.log** — alerts and noteworthy events
- **ssl.log** — SSL/TLS handshake info
- **smtp.log** — SMTP traffic
- **irc.log** — IRC traffic
- **dhcp.log** — DHCP activity
- **weird.log** — unusual network activity
- **x509.log** — certificate info
- **ssh.log** — SSH sessions
- **kerberos.log** — Kerberos auth info
- **radius.log** — RADIUS auth
- **zeek.log** — generic logs
### Zeek Tools
| Tool           | Purpose                        |
| -------------- | ------------------------------ |
| `zeek`         | Main engine to run scripts     |
| `zeekctl`      | Control and deploy Zeek        |
| `zeek-cut`     | Extract columns from logs      |
| `zeekfmt`      | Format Zeek scripts            |
| `zeek-dbg`     | Debug version of Zeek          |
| `zeek-config`  | Query Zeek install/config info |
| `zeek-addrgen` | Generate IPs for testing       |
| `zeekc`        | Legacy Zeek compiler           |

### **Live Capture**
```json
sudo zeek -i eth0
sudo zeek -i eth0 local.zeek
sudo zeek -i eth0 -i eth1
```

**Tips:**
- Use **sudo** for raw packet capture
- Consider **PCAP-over-IP** with `tcpdump -w - | nc` for live forwarding
- Test scripts on small PCAPs first
- Rotate logs regularly in live environments

**Zeek logs in a nutshell;**

Some of the most commonly used logs are explained in the given table.

| **Update Frequency** | **Log Name  <br>**   | **Description**                                 |
| -------------------- | -------------------- | ----------------------------------------------- |
| **Daily**            | _known_hosts.log_    | List of hosts that completed TCP handshakes.    |
| **Daily**            | _known_services.log_ | List of services used by hosts.                 |
| **Daily**            | _known_certs.log_    | List of SSL certificates.                       |
| **Daily**            | _software.log_       | List of software used on the network.           |
| **Per Session**      | _notice.log_         | Anomalies detected by Zeek.                     |
| **Per Session**      | _intel.log_          | Traffic contains malicious patterns/indicators. |
| Per Session          | _signatures.log_     | List of triggered signatures.                   |
**Brief log usage primer table;**

| **Overall Info**     | **Protocol Based** | **Detection**    | **Observation**      |
| -------------------- | ------------------ | ---------------- | -------------------- |
| _conn.log_           | _http.log_         | _notice.log_     | _known_host.log_     |
| _files.log_          | _dns.log_          | _signatures.log_ | _known_services.log_ |
| _intel.log_          | _ftp.log_          | _pe.log_         | _software.log_       |
| _loaded_scripts.log_ | _ssh.log_          | _traceroute.log_ | _weird.log_          |

### **Quick Log Analysis**
```json
zeek-cut id.orig_h id.resp_h proto service < conn.log
zeek-cut id.resp_h < conn.log | sort | uniq -c | sort -rn | head
awk '{print $1,$2,$3}' conn.log | sort | uniq -c | sort -rn | head
grep "suspicious" notice.log
cut -f1,2,3 conn.log | sort | uniq -c | sort -rn
jq '.' *.json  # if logs are JSON
```

### **File Extraction**
```cs
zeek -r sample.pcap --site-policy=policy/frameworks/files/extract-all-files.zeek
@load policy/frameworks/files/extract-http.zeek
@load policy/frameworks/files/extract-smb.zeek
@load policy/frameworks/files/extract-ftp.zeek
@load policy/frameworks/files/hash.zeek  # compute MD5/SHA1/SHA256
```
# Save files to custom directory
`redef FileExtract::default_extract_dir = "/tmp/zeek_files";`

### **Custom Local Script Example**
```json
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl
@load base/frameworks/notice

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
    if ( c?$http && c$http?$user_agent )
        print fmt("%s %s -> %s UA=%s", c$id$orig_h, method, unescaped_URI, c$http$user_agent);
}

event dns_query(c: connection, query: string, qclass: count, qtype: count)
{
    print fmt("%s DNS Query: %s", c$id$orig_h, query);
}

event ssl_established(c: connection)
{
    print fmt("%s SSL handshake detected", c$id$orig_h);
}

event new_connection(c: connection)
{
    print fmt("New connection: %s -> %s (%s)", c$id$orig_h, c$id$resp_h, c$id$resp_p);
}
```
# Run script
`zeek -r sample.pcap local.zeek`

### **zeekctl Commands**
```json
sudo zeekctl deploy
sudo zeekctl start
sudo zeekctl stop
sudo zeekctl restart
sudo zeekctl status
sudo zeekctl check
sudo zeekctl cron
sudo zeekctl rotate
sudo zeekctl config
```
### **Advanced Techniques**
- **zeek-cut** to extract columns from any log quickly
- Convert logs to **JSON** for ELK/Elastic ingestion
- Combine logs using `join`, `awk`, `grep`, or **Python** scripts
- Stream PCAP via **tcpdump | nc** for live Zeek analysis
- Load community packages with **zkg** (`zeek-pkg`) for detection rules, file analyzers, threat intel enrichment
- Custom event scripts for **IoC detection**, anomaly detection, or traffic correlation
- Apply **rate-limiting** or threshold detection
- Monitor **notice.log** for triggered alerts
- Enable **debug mode**: `zeek -r sample.pcap -d local.zeek`
- Enable **verbose mode**: `zeek -r sample.pcap -v`
- Use **policy frameworks**:
  - `policy/frameworks/conn-summary.zeek` — connection stats
  - `policy/frameworks/files/` — file extraction and analysis
  - `policy/frameworks/notice/` — automated alerts

### **Network Protocol Coverage**
- HTTP: `@load base/protocols/http`
- DNS: `@load base/protocols/dns`
- SMTP: `@load base/protocols/smtp`
- SSH: `@load base/protocols/ssh`
- SSL/TLS: `@load base/protocols/ssl`
- FTP: `@load policy/frameworks/files/extract-ftp.zeek`
- SMB: `@load policy/frameworks/files/extract-smb.zeek`
- DHCP: `@load base/protocols/dhcp`
- Kerberos: `@load base/protocols/kerberos`
- RADIUS: `@load base/protocols/radius`

### **Advanced Event Handling**
- Connection events: `new_connection`, `connection_state_remove`, `connection_established`
- Protocol-specific events: `http_request`, `http_response`, `dns_query`, `ssl_established`, `smtp_mail`
- Custom logging example:
```json
global my_log: log_id;

event zeek_init()  
{  
my_log = open_log("my_custom.log");  
}

event some_event(c: connection)  
{  
print my_log, fmt("%s triggered event", c$id$orig_h);  
}
```

### **Indicators of Compromise (IoC) Detection**
- Suspicious DNS queries: `grep -E "\.xyz$|\.top$|\.club$" dns.log`
- High-volume connections: analyze `conn.log` for unusual frequency
- Malicious user-agents: `grep -i "curl\|wget\|python" http.log`
- Suspicious file hashes: cross-check `files.log` hashes with threat intel
- Unusual ports: monitor `conn.log` for non-standard ports

### **PCAP Pipelines**
- Live capture to Zeek via Netcat:
`sudo tcpdump -i eth0 -s0 -U -w - not tcp port 57012 | nc localhost 57012`
- Merge PCAPs for analysis:
```cs
mergecap -w merged.pcap *.pcap
zeek -r merged.pcap
```

### **Integration & Automation**
- Combine Zeek logs with **Suricata**, **NetworkMiner**, **Wireshark**, or **ELK**
- Automate log parsing with **awk, grep, jq, Python**
- Stream logs to **SIEM** for alerts
- Docker/Kubernetes deployment for lab or production
- Use **cron jobs** for automated Zeek runs
- Use **zkg** to install community scripts:  
zkg install zeek/package_name

### **Tips & Best Practices**
- Always check **log write permissions**
- Use **local scripts** to avoid modifying base Zeek framework
- Modularize scripts for readability and maintainability
- Test scripts on small PCAPs before production
- Regularly update **Zeek packages** and **community scripts**
- Review **notice.log** for actionable alerts
- Document custom scripts for team sharing
- Combine **file extraction**, **hashing**, and **protocol correlation** for network forensics
- Use **rate-limiting scripts** to avoid false positives
- Maintain **consistent logging directories** for multi-node deployments
- Leverage **debug and verbose modes** for troubleshooting

