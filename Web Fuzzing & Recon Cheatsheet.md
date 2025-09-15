#recon #fuzzing #gobuster #ffuf

## FFUF (Fuzz Faster U Fool)

### Basic Directory Fuzzing

```bash
ffuf -u http://target/FUZZ -w /path/to/wordlist.txt
```

### Recursive Fuzzing

```bash
ffuf -u http://target/FUZZ -w /path/to/wordlist.txt -recursion
```

### Virtual Hosts / Subdomains

```bash
ffuf -u http://TARGET -H "Host: FUZZ.target.com" -w /path/to/subdomains.txt
```

### POST Request Fuzzing

```bash
ffuf -X POST -u http://target/login -d 'username=FUZZ&password=test' -w /path/to/usernames.txt
```

### API Fuzzing

```bash
ffuf -u http://target/api/FUZZ -w /path/to/api_endpoints.txt -H 'Authorization: Bearer TOKEN'
```

### Filters and Matchers

```bash
ffuf -u http://target/FUZZ -w /path/wordlist.txt -mc 200,301 -fs 1234 -ml 10
```

- **-mc** : match status codes
    
- **-fs** : filter by response size
    
- **-ml** : filter by line count
    

### Output Options

```bash
ffuf -u http://target/FUZZ -w /path/wordlist.txt -o result.json -of json
```

---

## Gobuster

### Basic Directory Scan

```bash
gobuster dir -u http://target/ -w /path/wordlist.txt
```

### Virtual Host / DNS Scan

```bash
gobuster vhost -u http://target/ -w /path/vhost_wordlist.txt
```

### Recursive Scan

```bash
gobuster dir -u http://target/ -w /path/wordlist.txt -r
```

### Extensions and Filtering

```bash
gobuster dir -u http://target/ -w /path/wordlist.txt -x php,txt,html -s 200,301,403
```

### Output Options

```bash
gobuster dir -u http://target/ -w /path/wordlist.txt -o output.txt
```

---

## Subdomain Enumeration

### Using FFUF

```bash
ffuf -u https://FUZZ.target.com -w subdomains.txt -mc 200
```

### Using Gobuster

```bash
gobuster dns -d target.com -w subdomains.txt
```

### Permutations / Brute-force

```bash
ffuf -u https://FUZZ.target.com -w subdomains.txt -recursion
```

---

## API Recon / Fuzzing

### REST API Endpoints

```bash
ffuf -u http://target/api/FUZZ -w endpoints.txt -H 'Authorization: Bearer TOKEN'
```

### AWS / Cloud API Endpoints

```bash
ffuf -u https://target/FUZZ -w aws_api_endpoints.txt -H 'x-api-key: APIKEY'
```

### GraphQL Fuzzing

```bash
ffuf -X POST -u http://target/graphql -d '{"query":"FUZZ"}' -w queries.txt -H 'Content-Type: application/json'
```

---

## FFUF Techniques

- **Recursive API fuzzing**: combine recursion with API endpoint discovery.
    
- **Header fuzzing**: `-H 'X-Header: FUZZ'`
    
- **Cookie fuzzing**: `-b 'session=FUZZ'`
    
- **Multiple wordlists**: `-w users.txt:U,pass.txt:P -d 'username=U&password=P'`
    
- **Follow redirects**: `-fr`
    
- **Match Regex**: `-mr 'success'`
    
- **Filter Regex**: `-fr 'error'`
    

---

## Tips & Tricks

- Always start with a small wordlist to validate endpoints.
    
- Use response size filtering to reduce noise.
    
- Combine status code, content length, line count filters.
    
- For AWS APIs, look for `s3`, `iam`, `lambda` endpoints.
    
- Chain vhost and directory fuzzing for hidden dashboards.
    
- Use `-mc 200,301,302,403` for common valid responses.
    
- Save all outputs in JSON/CSV for later analysis.
    

