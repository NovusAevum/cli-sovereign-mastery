# ⚡ CLI Sovereign Mastery - Quick Reference Card

**MPNS™ Protocol: The Foundation of Terminal Mastery**

```
M → mkdir    📁 Create structure
P → cd       🚶 Position yourself  
N → nano     ✍️ Craft content
S → run      💾 Execute & validate
```

---

## 🎖️ Boot Camp Essentials

### Navigation
```bash
pwd              # Where am I?
cd /path         # Go there
cd ..            # Go up
cd -             # Go back
ls -lah          # Show everything
tree -L 2        # Visual structure
```

### File Operations
```bash
mkdir -p a/b/c   # Create nested
touch file.txt   # Create file
cp -r src/ dst/  # Copy directory
mv old new       # Rename/move
rm -rf dir/      # Delete (DANGER!)
```

### Viewing Files
```bash
cat file.txt     # Show all
less file.txt    # Page through
head -20 file    # First 20 lines
tail -f log      # Follow live
```

---

## 👔 Officer Training Essentials

### Process Management
```bash
ps aux           # All processes
top              # Live monitor
kill PID         # Graceful stop
kill -9 PID      # Force kill
command &        # Background
jobs             # List jobs
fg %1            # Foreground job 1
```

### Networking
```bash
ip addr show     # Network config
ping host        # Test reach
ss -tulnp        # Open ports
curl URL         # HTTP request
wget -c URL      # Download
```

---

## 🛡️ Security Operations Essentials

### Reconnaissance
```bash
nmap -sn IP/24   # Host discovery
nmap -p- IP      # All ports
dig domain       # DNS lookup
whois domain     # Registration info
```

### SSH
```bash
ssh user@host    # Connect
ssh -L 8080:localhost:80 user@host  # Port forward
scp file user@host:/path/           # Copy file
ssh-keygen -t ed25519               # Generate key
```

### System Audit
```bash
find / -perm -4000 -type f 2>/dev/null  # SUID bins
sudo -l                                  # Sudo perms
cat /etc/passwd                          # Users
ss -tulnp                                # Open ports
```

---

## ⚡ Power User Shortcuts

### Command Line Editing
```
CTRL+A    # Start of line
CTRL+E    # End of line
CTRL+U    # Delete to start
CTRL+K    # Delete to end
CTRL+W    # Delete word
CTRL+R    # Search history
CTRL+L    # Clear screen
```

### History
```bash
history          # Show all
!123             # Run command 123
!!               # Repeat last
!$               # Last argument
```

### Pipes & Redirection
```bash
cmd > file       # Overwrite
cmd >> file      # Append
cmd 2>&1         # Redirect errors
cmd1 | cmd2      # Pipe
cmd1 && cmd2     # If success
cmd1 || cmd2     # If fail
```

---

## 📊 One-Liners (Production)

### Find large files
```bash
find / -type f -size +100M 2>/dev/null | xargs du -h | sort -rh | head
```

### Check disk usage
```bash
df -h | sort -k5 -rh | head
```

### Find recently modified
```bash
find /var/log -mtime -1 -type f -ls
```

### Kill processes by name
```bash
ps aux | grep process_name | grep -v grep | awk '{print $2}' | xargs kill
```

### Network connections count
```bash
ss -tan | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head
```

### Monitor bandwidth
```bash
watch -n 1 "ifstat -i eth0 1 1"
```

---

## 🔥 Emergency Commands

### System frozen?
```bash
# Magic SysRq key (Linux)
# ALT + SysRq + REISUB (slowly)
# R - keyboard control
# E - terminate all
# I - kill all
# S - sync disks
# U - unmount
# B - reboot
```

### Disk full?
```bash
# Find culprits
du -sh /* | sort -rh | head
ncdu /
# Clean up
sudo apt clean
rm -rf ~/.cache/*
```

### High load?
```bash
# Check what's using CPU
top -o %CPU
# Check I/O wait
iostat -x 2
# Kill CPU hog
kill -9 $(ps aux | sort -nrk 3,3 | head -1 | awk '{print $2}')
```

---

## 🎯 Repository Quick Start

```bash
# Clone repository
git clone https://github.com/novusaevum/cli-sovereign-mastery.git
cd cli-sovereign-mastery

# Check environment
./scripts/env-check.sh

# Create project
./scripts/project-scaffold.sh my-app python

# Start learning
cat docs/01-boot-camp/README.md
```

---

## 🏆 Certification Command Coverage

| Cert | Commands Covered |
|------|------------------|
| Linux+ | 60% |
| RHCSA | 70% |
| CEH | 80% |
| AWS SysOps | 65% |
| CKA | 55% |

---

## 📚 Essential Resources

- **Official Docs:** man command_name
- **Community:** https://unix.stackexchange.com
- **Practice:** https://overthewire.org
- **Security:** https://tryhackme.com

---

## ⚠️ Safety Rules

1. **Always** verify your location: `pwd`
2. **Never** run `rm -rf /` (obvious but worth stating)
3. **Test** destructive commands with `echo` first
4. **Backup** before bulk operations
5. **Use** version control for everything
6. **Validate** user input in scripts
7. **Check** exit codes: `$?`
8. **Quote** variables: `"$VAR"` not `$VAR`

---

## 🚀 Daily Workflow

```bash
# Morning routine
cd ~/projects
git pull
./scripts/env-check.sh

# MPNS Cycle
mkdir -p project/feature
cd project/feature
nano implementation.py
python implementation.py

# Evening routine
git add .
git commit -m "feat: implement feature"
git push
```

---

**Print this card. Pin it to your wall. Master these commands.**

**Then teach others.**

---

*From the CLI Sovereign Mastery Framework*  
*By Wan Mohamad Hanis bin Wan Hassan*

**📍 Repository:** https://github.com/novusaevum/cli-sovereign-mastery  
**📧 Author:** [LinkedIn](https://www.linkedin.com/in/wanmohamadhanis)
