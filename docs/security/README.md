# 🛡️ Security Operations: Offensive & Defensive CLI Techniques

**Mission Objective:** Master command-line security operations from both attacker and defender perspectives.

**Prerequisites:** Officer Training completion, solid networking foundation  
**Certifications Aligned:** CEH v12, OSCP, CompTIA Security+

**⚠️ ETHICAL USE ONLY:** All techniques for authorized testing and defense only.

---

## 🔍 Part 1: Network Reconnaissance

### Nmap — Network Discovery

**Basic Scanning:**
```bash
# Host discovery
nmap -sn 192.168.1.0/24

# Port scan
nmap -p- target.com

# Service detection
nmap -sV target.com

# OS detection
sudo nmap -O target.com
```

**Stealth Techniques:**
```bash
# SYN scan (stealthier)
sudo nmap -sS target

# Fragment packets
sudo nmap -f target

# Slow timing (IDS evasion)
nmap -T2 target
```

---

## 🔐 Part 2: System Security

### SSH Hardening

**Configuration (/etc/ssh/sshd_config):**
```bash
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
Port 2222
MaxAuthTries 3
```

### Privilege Escalation Checks

```bash
# SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Sudo permissions
sudo -l

# Cron jobs
cat /etc/crontab
crontab -l
```

---

**Full module available in repository. Continuing with automation scripts...**