# 🎯 Special Operations: Advanced Tactical CLI Mastery

**Mission Objective:** Master advanced command-line operations that separate professionals from experts.  
**Skill Level:** Advanced - Requires completion of Boot Camp, Officer Training, and Security modules  
**Time Investment:** 30+ hours for competency, continuous practice for mastery

---

## 🎖️ Special Operations Philosophy

**Special operations forces operate where conventional forces cannot.** This module covers advanced techniques for system administration, sophisticated automation, performance optimization, and enterprise-scale operations. You'll learn to orchestrate complex multi-system workflows, optimize for extreme scale, and troubleshoot the "impossible" problems.

---

## PART 1: ADVANCED SHELL SCRIPTING

### Professional Script Architecture

**Enterprise-Grade Bash Script Template:**
```bash
#!/usr/bin/env bash
###############################################################################
# Script Name: production-deploy.sh
# Description: Zero-downtime deployment orchestration
# Author: Wan Mohamad Hanis
# Version: 2.1.0
# Dependencies: ssh, rsync, docker
# Usage: ./production-deploy.sh [--env staging|prod] [--rollback]
###############################################################################

set -euo pipefail  # Exit on error, undefined vars, pipe failures
IFS=$'\n\t'        # Secure Internal Field Separator

# Global variables
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_NAME="$(basename "$0")"
readonly LOG_FILE="/var/log/${SCRIPT_NAME%.sh}_$(date +%Y%m%d).log"
readonly LOCK_FILE="/var/lock/${SCRIPT_NAME%.sh}.lock"

# Color output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] ${GREEN}INFO${NC}: $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] ${RED}ERROR${NC}: $*" | tee -a "$LOG_FILE" >&2
}

log_warn() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] ${YELLOW}WARN${NC}: $*" | tee -a "$LOG_FILE"
}

# Cleanup on exit
cleanup() {
    local exit_code=$?
    log_info "Cleaning up..."
    rm -f "$LOCK_FILE"
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

# Lock file mechanism (prevent concurrent execution)
acquire_lock() {
    if [ -f "$LOCK_FILE" ]; then
        local lock_pid=$(cat "$LOCK_FILE")
        if ps -p "$lock_pid" > /dev/null 2>&1; then
            log_error "Script already running (PID: $lock_pid)"
            exit 1
        else
            log_warn "Removing stale lock file"
            rm -f "$LOCK_FILE"
        fi
    fi
    echo $$ > "$LOCK_FILE"
}

# Validate prerequisites
validate_environment() {
    log_info "Validating environment..."
    
    # Check required commands
    local required_commands=("ssh" "rsync" "docker" "jq")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command not found: $cmd"
            exit 1
        fi
    done
    
    # Check environment variables
    if [ -z "${DEPLOY_KEY:-}" ]; then
        log_error "DEPLOY_KEY environment variable not set"
        exit 1
    fi
    
    log_info "Environment validation complete"
}

# Argument parsing
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --env)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --rollback)
                ROLLBACK=true
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Validate required arguments
    if [ -z "${ENVIRONMENT:-}" ]; then
        log_error "Environment not specified"
        show_usage
        exit 1
    fi
}

show_usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

Options:
    --env ENV       Target environment (staging|prod)
    --rollback      Rollback to previous version
    --help          Show this help message

Examples:
    $SCRIPT_NAME --env staging
    $SCRIPT_NAME --env prod --rollback

EOF
}

# Main deployment logic
main() {
    acquire_lock
    parse_arguments "$@"
    validate_environment
    
    log_info "Starting deployment to $ENVIRONMENT"
    
    # Your deployment logic here
    deploy_application
    run_health_checks
    
    log_info "Deployment completed successfully"
}

# Execute main function with all script arguments
main "$@"
```

---

### Advanced Shell Techniques

**Parameter Expansion Mastery:**
```bash
# Default values
${VAR:-default}          # Use default if VAR unset
${VAR:=default}          # Assign default if VAR unset
${VAR:?error message}    # Exit with error if VAR unset
${VAR:+alternate}        # Use alternate if VAR is set

# String manipulation
${VAR#pattern}           # Remove shortest match from start
${VAR##pattern}          # Remove longest match from start
${VAR%pattern}           # Remove shortest match from end
${VAR%%pattern}          # Remove longest match from end

# Example: Extract filename and extension
filepath="/path/to/document.tar.gz"
filename="${filepath##*/}"           # document.tar.gz
basename="${filename%%.*}"           # document
extension="${filename#*.}"           # tar.gz
first_ext="${filename##*.}"          # gz

# Case modification
${VAR^}                  # Uppercase first character
${VAR^^}                 # Uppercase all
${VAR,}                  # Lowercase first character
${VAR,,}                 # Lowercase all

# Length and substring
${#VAR}                  # Length of VAR
${VAR:offset:length}     # Substring

# Search and replace
${VAR/pattern/replacement}   # Replace first match
${VAR//pattern/replacement}  # Replace all matches
```

**Process Substitution:**
```bash
# Compare outputs of two commands
diff <(ls dir1) <(ls dir2)

# Use command output as file input
while IFS= read -r line; do
    echo "Processing: $line"
done < <(find /path -name "*.log")

# Multiple process substitutions
paste <(cat file1) <(cat file2) <(cat file3)
```

**Here Documents and Here Strings:**
```bash
# Here document (multiline)
cat << 'EOF' > config.txt
server {
    listen 80;
    server_name $HOSTNAME;
    root /var/www/html;
}
EOF

# Here document with variable expansion
cat << EOF > script.sh
#!/bin/bash
echo "User: $(whoami)"
echo "Date: $(date)"
EOF

# Here string (single line)
grep "pattern" <<< "string to search"
```

---

## PART 2: ADVANCED TEXT PROCESSING

### Awk Programming

**Complex Data Extraction:**
```bash
# Apache log analysis (top 10 IPs by request count)
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -10

# Calculate average response time
awk '{sum+=$10; count++} END {print "Average:", sum/count "ms"}' access.log

# Filter by HTTP status code and calculate bandwidth
awk '$9 == 200 {bytes+=$10} END {print "Bandwidth:", bytes/1024/1024 "MB"}' access.log

# Complex conditional logic
awk '
    $9 >= 400 && $9 < 500 { client_errors++ }
    $9 >= 500 { server_errors++ }
    END {
        print "Client Errors (4xx):", client_errors
        print "Server Errors (5xx):", server_errors
    }
' access.log

# Multi-file processing with functions
awk '
    function format_bytes(bytes) {
        if (bytes >= 1073741824) return sprintf("%.2f GB", bytes/1073741824)
        if (bytes >= 1048576) return sprintf("%.2f MB", bytes/1048576)
        if (bytes >= 1024) return sprintf("%.2f KB", bytes/1024)
        return bytes " B"
    }
    
    { total_bytes += $10 }
    
    END {
        print "Total bandwidth:", format_bytes(total_bytes)
    }
' *.log
```

### Sed Stream Editing

**Advanced Pattern Manipulation:**
```bash
# In-place editing with backup
sed -i.bak 's/old/new/g' file.txt

# Multi-line replacements
sed ':a;N;$!ba;s/pattern\nmultiline/replacement/g' file.txt

# Delete lines matching pattern
sed '/DEBUG/d' logfile.txt

# Print only lines between patterns
sed -n '/START/,/END/p' file.txt

# Complex substitutions with capture groups
sed 's/\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)/IP: \1.\2.\3.\4/g'

# Conditional replacements
sed '/pattern/s/old/new/g' file.txt  # Replace only in lines matching pattern

# Insert/append lines
sed '5i\New line to insert' file.txt  # Insert before line 5
sed '5a\New line to append' file.txt  # Append after line 5
```

### Grep Advanced Techniques

**Context-Aware Searching:**
```bash
# Context lines
grep -A 3 "ERROR" logfile.txt     # 3 lines after match
grep -B 3 "ERROR" logfile.txt     # 3 lines before match
grep -C 3 "ERROR" logfile.txt     # 3 lines before and after

# Recursive search with file patterns
grep -r --include="*.py" "TODO" /project/

# Exclude directories
grep -r --exclude-dir={.git,node_modules,venv} "pattern" /project/

# Perl-compatible regex (more powerful)
grep -P '(?<=User: )\w+' file.txt  # Lookbehind assertion

# Count matches per file
grep -c "ERROR" *.log | sort -t: -k2 -rn

# Inverse grep (lines NOT matching)
grep -v "DEBUG\|INFO" logfile.txt

# Multiple patterns (OR)
grep -E "ERROR|CRITICAL|FATAL" logfile.txt

# Binary file search
grep -a "pattern" binaryfile  # Treat binary as text
```

---

## PART 3: PERFORMANCE OPTIMIZATION

### System Performance Analysis

**CPU Performance:**
```bash
# Real-time CPU monitoring per core
mpstat -P ALL 1

# Process CPU usage
top -b -n 1 | head -20

# CPU-intensive process identification
ps aux --sort=-%cpu | head -10

# CPU affinity (pin process to specific cores)
taskset -c 0,1 ./cpu_bound_process  # Run on cores 0 and 1

# Check CPU throttling
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Prevent CPU throttling (performance mode)
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance | sudo tee $cpu
done
```

**Memory Optimization:**
```bash
# Memory usage breakdown
free -h
vmstat 1 5  # Virtual memory statistics (1 sec intervals, 5 times)

# Per-process memory analysis
ps aux --sort=-%mem | head -10
smem -r -k  # More accurate (considers shared memory)

# Memory leak detection
# Monitor process over time
while true; do
    ps aux | grep process_name | grep -v grep | awk '{print $6}'
    sleep 60
done

# Drop caches (free up memory - careful in production!)
echo 3 | sudo tee /proc/sys/vm/drop_caches

# Huge pages for performance (databases, VMs)
sudo sysctl vm.nr_hugepages=1024
```

**I/O Performance:**
```bash
# Disk I/O statistics
iostat -x 1 5  # Extended stats, 1 sec intervals

# Per-process I/O
iotop

# Find processes causing high I/O wait
pidstat -d 1

# Filesystem performance test
dd if=/dev/zero of=testfile bs=1G count=1 oflag=direct

# IOPS testing
fio --name=random-read --ioengine=libaio --iodepth=16 --rw=randread --bs=4k --direct=1 --size=1G --numjobs=4 --runtime=60 --group_reporting

# Identify slow queries on filesystem
inotifywatch -v -e modify -e create -e delete -t 60 -r /path/
```

---

## PART 4: ADVANCED NETWORKING

### Network Traffic Analysis

**Packet Capture and Analysis:**
```bash
# Capture specific traffic
tcpdump -i eth0 'tcp port 80 and (src net 192.168.1.0/24)'

# Save to file for later analysis
tcpdump -i eth0 -w capture.pcap

# Read and filter pcap file
tcpdump -r capture.pcap 'tcp[tcpflags] & tcp-syn != 0'

# Extract HTTP requests
tcpdump -i eth0 -A 'tcp port 80' | grep -E 'GET|POST'

# SSL/TLS analysis
ssldump -i eth0 -k server.key

# Advanced tshark filtering
tshark -r capture.pcap -Y 'http.request.method == "POST"' -T fields -e http.request.uri -e ip.src

# Bandwidth per IP
tcpdump -i eth0 -nn -q | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -rn
```

**Network Performance Tuning:**
```bash
# TCP buffer tuning (high-throughput networks)
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.wmem_max=134217728
sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 67108864"
sudo sysctl -w net.ipv4.tcp_wmem="4096 65536 67108864"

# Connection tracking optimization
sudo sysctl -w net.netfilter.nf_conntrack_max=1000000

# Increase file descriptors for high connection count
ulimit -n 65535

# Test network throughput
iperf3 -s  # Server
iperf3 -c server_ip -t 30 -P 10  # Client: 30 sec, 10 parallel streams
```

---

**Special Operations module establishing advanced capabilities...**

**Continuing with remaining sections (Strategic Command, Cloud, Containers, Automation, Monitoring)...**

---

## PART 5: ADVANCED DATA PROCESSING & TRANSFORMATION

### JSON Processing with jq

Modern systems communicate through JSON APIs, making JSON processing essential for advanced operations. The `jq` tool is a powerful JSON processor that lets you query, filter, and transform JSON data with elegance.

**Basic jq Operations:**
```bash
# Pretty-print JSON
echo '{"name":"hanis","age":30}' | jq '.'

# Extract specific field
echo '{"name":"hanis","age":30}' | jq '.name'
# Output: "hanis"

# Extract from array
echo '[{"name":"alice"},{"name":"bob"}]' | jq '.[0].name'
# Output: "alice"

# Filter array elements
echo '[{"name":"alice","age":25},{"name":"bob","age":30}]' | jq '.[] | select(.age > 25)'

# Map transformation
echo '[1,2,3,4,5]' | jq 'map(. * 2)'
# Output: [2,4,6,8,10]

# Combine fields
echo '{"first":"Wan","last":"Hanis"}' | jq '.first + " " + .last'
# Output: "Wan Hanis"
```

**Real-World API Processing:**
```bash
# Parse AWS CLI JSON output
aws ec2 describe-instances | jq '.Reservations[].Instances[] | {id: .InstanceId, state: .State.Name, ip: .PrivateIpAddress}'

# Extract specific fields from curl response
curl -s https://api.github.com/users/novusaevum | jq '{name: .name, repos: .public_repos, followers: .followers}'

# Filter and count
curl -s https://api.github.com/users/novusaevum/repos | jq '[.[] | select(.language == "Python")] | length'
```

---

## PART 6: SYSTEM MONITORING & DIAGNOSTICS

### Real-Time System Analysis

Professional operators need to diagnose problems quickly under pressure. These techniques enable rapid system assessment and troubleshooting.

**Comprehensive System Health Check:**
```bash
#!/bin/bash
# Rapid system diagnostics

echo "=== System Health Check ==="
echo "Timestamp: $(date)"
echo ""

# CPU Information
echo "CPU Cores: $(nproc)"
echo "CPU Load (1/5/15 min): $(uptime | awk -F'load average:' '{print $2}')"
echo ""

# Memory Status
free -h | awk 'NR==2{printf "Memory Usage: %s/%s (%.2f%%)\n", $3,$2,$3*100/$2}'
echo ""

# Disk Usage (critical only)
echo "Disk Usage (>80%):"
df -h | awk 'NR>1 && $5+0 > 80 {print $6 ": " $5}'
echo ""

# Network Connectivity
echo "Network Status:"
ping -c 1 8.8.8.8 > /dev/null 2>&1 && echo "✓ Internet: Connected" || echo "✗ Internet: Disconnected"
echo ""

# Top CPU Consumers
echo "Top 5 CPU Processes:"
ps aux --sort=-%cpu | head -6 | tail -5 | awk '{printf "%-10s %5s%% %s\n", $1, $3, $11}'
echo ""

# Top Memory Consumers
echo "Top 5 Memory Processes:"
ps aux --sort=-%mem | head -6 | tail -5 | awk '{printf "%-10s %5s%% %s\n", $1, $4, $11}'
```

**Log Analysis Patterns:**
```bash
# Real-time error monitoring with context
tail -f /var/log/syslog | grep --line-buffered -i error | while read line; do
    echo "$(date '+%H:%M:%S') - $line"
    # Could send to monitoring system here
done

# Analyze patterns in logs
# Find most common errors
grep -i error /var/log/application.log | \
    sed 's/.*ERROR: //' | \
    sort | uniq -c | sort -rn | head -10

# Time-based log analysis
awk '/2025-10-20/ && /ERROR/' /var/log/app.log | \
    cut -d' ' -f1-3 | uniq -c
```

---

## PART 7: ADVANCED FILE OPERATIONS

### Symbolic Links and Hard Links

Understanding links is crucial for efficient file management and understanding Unix file systems.

**Symbolic Links (Soft Links):**
```bash
# Create symbolic link
ln -s /path/to/original /path/to/link

# Real-world use: Version management
ln -s /opt/app/version-2.0 /opt/app/current
# Upgrade by changing link:
ln -snf /opt/app/version-3.0 /opt/app/current

# Verify link
ls -l /opt/app/current
# Output: current -> /opt/app/version-3.0

# Find broken symlinks
find /path -type l ! -exec test -e {} \; -print
```

**Hard Links:**
```bash
# Create hard link (same inode, different name)
ln /path/to/original /path/to/hardlink

# Both names refer to same data
ls -li /path/to/original /path/to/hardlink
# Same inode number = same file

# Use case: Backups without duplicating data
cp -l original.txt backup.txt  # Hard link copy
```

---

## 🎖️ Special Operations Mastery Achieved

You've completed Special Operations training and achieved advanced command-line proficiency. You're now capable of enterprise-level system administration, sophisticated automation, and complex problem-solving under pressure.

**Your Advanced Capabilities:**

You can architect and implement production-grade automation scripts with proper error handling, logging, and maintainability. Your text processing skills enable sophisticated data analysis and transformation. You understand performance optimization at the system level, allowing you to diagnose and resolve bottlenecks. Your networking knowledge extends beyond basics to advanced traffic analysis and security considerations.

**Professional Application:**

These skills distinguish senior engineers from intermediate practitioners. You can now optimize application performance through system-level tuning, automate complex deployment workflows across multiple servers, troubleshoot production incidents rapidly using advanced diagnostic techniques, and design robust automation that handles edge cases gracefully.

**The Path Forward:**

Special Operations represents professional-grade capability. You're equipped for roles like Site Reliability Engineer, DevOps Engineer, and Senior System Administrator. These positions require exactly the skills you've mastered: automation, optimization, troubleshooting, and architectural thinking.

**What's Next:**

You're ready for Strategic Command, where you'll learn infrastructure as code, multi-cloud orchestration, and enterprise architecture patterns. This is where individual expertise scales to organizational impact. The foundation you've built enables you to architect systems that serve millions of users reliably.

**Continue Your Journey:** [Strategic Command Module](../04-strategic-command/README.md)

---

**Module Status:** ✅ COMPLETE  
**Skill Level:** Advanced Professional Operations  
**Time to Mastery:** 40+ hours of practice plus real-world application  
**Prerequisites for Next Module:** Comfort with all advanced techniques and automation patterns

**Author:** Wan Mohamad Hanis bin Wan Hassan  
**Framework:** CLI Sovereign Mastery | MPNS™ Methodology  
**Certifications:** CEH v12, AWS/GCP/Azure Architect, 100+ Professional Certifications  
**Last Updated:** October 20, 2025
