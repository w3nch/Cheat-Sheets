#phishing #guide

# Important Notice 
- all analysis should be done inside a sandbox 

### What is Phishing
Phishing is a **social engineering attack** where an attacker tricks a user into revealing sensitive information (credentials, financial data) or performing unsafe actions (clicking a malicious link, opening an attachment, enabling macros).

- Delivered mainly via **email**, but also via SMS (smishing), voice calls (vishing), or social platforms.
    
- The attacker pretends to be a **trusted entity** (bank, company, colleague, IT admin).
    
- Goal: steal credentials, deliver malware, or gain initial access into an organization.
### Why is it effective
Phishing works because it exploits **human behavior** more than technical flaws:

- **Trust & urgency:** Messages often impersonate bosses, banks, or services with “urgent” actions.
    
- **Lack of awareness:** Users may not recognize malicious links, spoofed addresses, or suspicious attachments.
    
- **High volume:** Attackers can send thousands of emails at almost no cost — even a tiny success rate is valuable.
    
- **Realism:** Modern phishing emails often look professional, using company logos, spoofed domains, or compromised accounts.
    
- **Evasion:** Attackers constantly change domains, payloads, and wording to bypass security filters.

### Importance Of Phishing Email Analysis
For a SOC analyst, phishing email analysis is critical because:

- **Most common attack vector:** Over 80% of breaches begin with phishing.
    
- **Early detection:** Analyzing suspicious emails quickly can stop credential theft or malware spread before escalation.
    
- **Threat intel:** Extracting indicators (malicious IPs, domains, attachments, hashes) helps enrich threat databases and block future attacks.
    
- **Awareness training:** Real-world phishing samples help train employees to recognize threats.
    
- **Incident response:** Proper analysis helps determine whether a phishing attempt was **just a lure** or delivered a **payload/beacon** into the environment.
    

**In practice, a SOC analyst will:**

- Examine email headers (sender IP, SPF/DKIM/DMARC results).
    
- Check embedded URLs (look for lookalike domains, redirects, shortened links).
    
- Analyze attachments (macro-enabled docs, executables, PDFs with scripts).
    
- Cross-check IOCs (IP, domain, hash) against threat intel feeds.
    
- Report and block (SIEM correlation, email quarantine, user awareness).
### Common Indicators of Phishing Emails
- Red Flags
	- sus sender addresses
	- unexpected attachments
	- grammatical errors
	- Urgent Language
	- Social Enginerring tactics

### Tools and Techniques for  Phishing Email Analysis
-  Overview of Tools
	1. Email headers analysis
	2. Sandboxes
	3. Link Cheakers
- Methodology
	1. Examining Emails Headers
	2. Inspecting Attachments
	3. Verifying Links
- Importance of Documentation
	1. Record Keeping notes
	2. Reporting
- TOOLS :
	  1. [Phishtool](https://app.phishtool.com/sign-up/community) analyse phishing emails full on tool
	  2. [Gophish](https://getgophish.com/) red team send phishing email
	  3. [Browserling](https://www.browserling.com/) brows a link with it
	  4. [urlscan.io](https://urlscan.io/) scans urls
	  5. [url2png](https://www.url2png.com/) get images 
### Email Artifacts
- Sending Email address : spoofing address , tactics and techniques
- Subject Line 
- Recipient Email address
- Sending Server IP and Reverse DNS:  where the email originated Tool MXToolBox
- Reply To address : 
- Date and Time
### File Artifacts
- Attachement Name
- SHA256 Hash value
### Web Artifacts
- Full URLS
- Root Domain
### Future of Phishing

