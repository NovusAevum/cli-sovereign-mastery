 Easier process management
- Visual CPU, memory, and swap meters
- Search and filter capabilities

---

### `kill` — Terminate Processes

**Purpose:** Send signals to processes (terminate, pause, continue)  
**Syntax:** `kill [SIGNAL] PID`

**Common Signals:**
```bash
kill PID                   # Send SIGTERM (15) - graceful shutdown
kill -9 PID                # Send SIGKILL (9) - force immediate termination
kill -15 PID               # Explicit SIGTERM
kill -STOP PID             # Pause process (SIGSTOP)
kill -CONT PID             # Resume paused process (SIGCONT)
kill -HUP PID              # Hang up (SIGHUP) - often triggers reload
kill -USR1 PID             # User-defined signal 1
kill -USR2 PID             # User-defined signal 2
```

**Signal Reference:**
| Signal | Number | Description | Use Case |
|--------|--------|-------------|----------|
| SIGHUP | 1 | Hangup | Reload configuration |
| SIGINT | 2 | Interrupt | Ctrl+C from keyboard |
| SIGQUIT | 3 | Quit | Ctrl+\ from keyboard |
| SIGKILL | 9 | Kill | Force termination (unblockable) |
| SIGTERM | 15 | Terminate | Graceful shutdown (default) |
| SIGSTOP | 19 | Stop | Pause process (unblockable) |
| SIGCONT | 18 | Continue | Resume stopped process |

**Best Practices:**
```bash
# Always try graceful termination first
kill PID               # Try SIGTERM
sleep 5                # Wait 5 seconds
kill -0 PID 2>/dev/null && kill -9 PID  # Force kill if still running

# Kill multiple processes by name
pkill nginx            # All nginx processes
killall firefox        # All firefox processes

# Kill process tree (parent and all children)
kill -TERM -$(ps -o pgid= PID | grep -o '[0-9]*')
```

**Security Context:**
```bash
# Red Team: Process manipulation for persistence
kill -STOP legitimate_process  # Suspend legitimate process
./backdoor &                   # Start backdoor in background
kill -CONT legitimate_process  # Resume legitimate process

# Blue Team: Detect suspicious process behavior
ps aux | grep -E 'STAT.*[TZ]' # Find stopped or zombie processes
```

**Enterprise Process Termination Script:**
```bash
#!/bin/bash
# Graceful process termination with fallback

terminate_process() {
    local pid="$1"
    local max_wait="${2:-30}"  # Default 30 seconds
    local wait_interval=2
    local elapsed=0
    
    # Validate PID
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "Process $pid not found or no permission"
        return 1
    fi
    
    echo "Sending SIGTERM to PID $pid..."
    kill -TERM "$pid"
    
    # Wait for graceful shutdown
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$elapsed" -ge "$max_wait" ]; then
            echo "Timeout reached. Forcing termination..."
            kill -KILL "$pid"
            sleep 1
            if kill -0 "$pid" 2>/dev/null; then
                echo "ERROR: Failed to terminate PID $pid"
                return 1
            fi
            echo "Process $pid force terminated (SIGKILL)"
            return 0
        fi
        
        sleep "$wait_interval"
        elapsed=$((elapsed + wait_interval))
        echo "Waiting for process to terminate... (${elapsed}s/${max_wait}s)"
    done
    
    echo "Process $pid terminated gracefully"
    return 0
}

# Usage
terminate_process 1234 45  # PID 1234, max wait 45 seconds
```

---

### Background Processes & Job Control

**Running Processes in Background:**
```bash
# Start process in background
command &              # Trailing ampersand

# Example
python3 long_script.py &     # Returns immediately with job number
# Output: [1] 5678 (job number and PID)

# Move running process to background
# 1. Press Ctrl+Z to suspend
# 2. Type: bg
```

**Job Management:**
```bash
jobs                   # List background jobs
jobs -l                # Include PIDs
fg                     # Bring last background job to foreground
fg %1                  # Bring job 1 to foreground
bg %1                  # Resume job 1 in background
kill %1                # Kill job 1
disown %1              # Detach job from shell (survives logout)
```

**Practical Examples:**
```bash
# Long-running compilation in background
make build > build.log 2>&1 &

# Multiple background jobs
./server1.sh &
./server2.sh &
./server3.sh &
jobs                   # View all three

# Keep process running after logout
nohup python3 server.py > server.log 2>&1 &

# Alternative: Use screen or tmux for persistent sessions
screen -dmS myserver python3 server.py
screen -r myserver     # Reattach to session
```

---

### `nice` & `renice` — Process Priority

**Purpose:** Control process CPU priority  
**Priority Range:** -20 (highest) to 19 (lowest), default is 0

**Nice — Start with Priority:**
```bash
nice -n 10 command         # Start with priority +10 (lower priority)
nice -n -5 command         # Requires root (higher priority)
nice command               # Default nice value (usually +10)
```

**Renice — Change Running Process Priority:**
```bash
renice -n 5 -p PID         # Change process priority
renice -n 10 -u username   # All processes of user
renice -n -5 -p PID        # Requires root privileges
```

**Real-World Scenarios:**
```bash
# Background compilation (low priority)
nice -n 15 make -j8 > build.log 2>&1 &

# Critical database backup (high priority - requires root)
sudo nice -n -10 pg_dump database > backup.sql

# Batch processing without impacting system
nice -n 19 ./batch_processor.sh
```

---

## 🌐 Part 2: Networking Operations

### Network Configuration

#### `ifconfig` / `ip` — Network Interface Configuration

**Modern Approach: `ip` command (replaces ifconfig)**

**Display Network Interfaces:**
```bash
ip addr show           # All interfaces with IP addresses
ip addr show eth0      # Specific interface
ip -4 addr             # IPv4 only
ip -6 addr             # IPv6 only
ip link show           # Link layer information
```

**Interface Management:**
```bash
# Bring interface up/down (requires root)
sudo ip link set eth0 up
sudo ip link set eth0 down

# Add IP address
sudo ip addr add 192.168.1.100/24 dev eth0

# Delete IP address
sudo ip addr del 192.168.1.100/24 dev eth0
```

**Legacy ifconfig (still useful for quick checks):**
```bash
ifconfig               # All interfaces
ifconfig eth0          # Specific interface
```

---

#### `ping` — Network Connectivity Test

**Purpose:** Test reachability and measure round-trip time

**Common Usage:**
```bash
ping hostname          # Continuous ping (Ctrl+C to stop)
ping -c 4 hostname     # Send 4 packets then stop
ping -i 0.5 hostname   # Ping every 0.5 seconds
ping -s 1000 hostname  # Packet size 1000 bytes
ping -W 2 hostname     # Timeout 2 seconds
```

**Advanced Diagnostics:**
```bash
# Test local network
ping -c 4 192.168.1.1      # Default gateway

# Test internet connectivity
ping -c 4 8.8.8.8          # Google DNS (IP)
ping -c 4 google.com       # Test DNS resolution too

# Flood ping (requires root, testing only!)
sudo ping -f target        # Maximum speed

# Record route (traceroute-like)
ping -R google.com         # Show route taken
```

**Security Reconnaissance:**
```bash
# Scan subnet for live hosts (basic)
for ip in 192.168.1.{1..254}; do
    ping -c 1 -W 1 $ip &>/dev/null && echo "$ip is up"
done

# Better alternative: use nmap (covered in Special Operations)
```

---

#### `netstat` / `ss` — Network Statistics

**Modern Approach: `ss` command (faster than netstat)**

**Display Network Connections:**
```bash
ss -tuln               # TCP/UDP listening ports (numeric)
ss -tulnp              # Include process info (requires root for all)
ss -s                  # Summary statistics
ss -t                  # TCP connections only
ss -u                  # UDP connections only
ss -a                  # All sockets
```

**Practical Examples:**
```bash
# Find what's listening on specific port
ss -tulnp | grep :80

# Show established connections
ss -t state established

# Count connections by state
ss -tan | awk '{print $1}' | sort | uniq -c

# Monitor connections in real-time
watch -n 1 'ss -s'
```

**Legacy netstat:**
```bash
netstat -tuln          # Listening ports
netstat -tulnp         # With process names
netstat -r             # Routing table
netstat -i             # Interface statistics
netstat -s             # Protocol statistics
```

**Security Auditing:**
```bash
# Identify suspicious listening ports
sudo ss -tulnp | grep LISTEN

# Detect reverse shells (look for unexpected outbound connections)
ss -tnp | grep ESTABLISHED | grep -v ':22\|:80\|:443'

# Find processes with most connections
ss -tnp | awk '/ESTAB/ {print $6}' | cut -d',' -f2 | cut -d'=' -f2 | sort | uniq -c | sort -rn | head
```

---

#### `curl` & `wget` — HTTP Clients

**curl — Transfer Data with URLs**

**Basic Usage:**
```bash
curl URL               # Display response body
curl -o file.html URL  # Save to file
curl -O URL            # Save with remote filename
curl -I URL            # Headers only (HEAD request)
curl -v URL            # Verbose (show request/response headers)
curl -s URL            # Silent mode
```

**Advanced Operations:**
```bash
# POST request with data
curl -X POST -d "key=value" URL

# JSON POST
curl -X POST -H "Content-Type: application/json" \
     -d '{"key":"value"}' URL

# Authentication
curl -u username:password URL

# Follow redirects
curl -L URL

# Custom headers
curl -H "Authorization: Bearer token" URL

# Upload file
curl -F "file=@/path/to/file" URL

# Multiple parallel downloads
curl -O URL1 -O URL2 -O URL3

# Rate limiting
curl --limit-rate 100K URL

# Resume download
curl -C - -O URL
```

**wget — Non-Interactive Downloader**

**Common Usage:**
```bash
wget URL               # Download file
wget -O filename URL   # Save with specific name
wget -c URL            # Continue incomplete download
wget -b URL            # Background download
wget -r URL            # Recursive download (entire website)
wget -np -r URL        # Recursive, no parent directories
wget --mirror URL      # Mirror website
```

**Enterprise Download Script:**
```bash
#!/bin/bash
# Robust file download with validation

download_file() {
    local url="$1"
    local output="${2:-$(basename "$url")}"
    local max_retries=3
    local timeout=30
    
    for attempt in $(seq 1 $max_retries); do
        echo "Attempt $attempt of $max_retries: Downloading $url"
        
        if curl -f -L --connect-timeout "$timeout" \
                --max-time $((timeout * 2)) \
                -o "$output" "$url"; then
            echo "Download successful: $output"
            
            # Verify file is not empty
            if [ -s "$output" ]; then
                echo "File size: $(du -h "$output" | cut -f1)"
                return 0
            else
                echo "Error: Downloaded file is empty"
                rm -f "$output"
            fi
        fi
        
        echo "Download failed. Retrying in 5 seconds..."
        sleep 5
    done
    
    echo "ERROR: Failed to download after $max_retries attempts"
    return 1
}

# Usage
download_file "https://example.com/file.tar.gz" "backup/file.tar.gz"
```

---

**Officer Training foundation established. Ready to continue with:**
- Shell Scripting fundamentals
- Text processing (grep, sed, awk)
- System monitoring and logging
- Or move to Special Operations (Security & Advanced Techniques)

**Your command, General.**
    echo "Error: Command failed!" >&2
    exit 1
fi

# Function error handling
safe_command() {
    local output
    if output=$(risky_command 2>&1); then
        echo "Success: $output"
        return 0
    else
        echo "Error: Command failed with output: $output" >&2
        return 1
    fi
}

# Trap for cleanup on exit
cleanup() {
    echo "Cleaning up temporary files..."
    rm -f /tmp/script_temp_*
}
trap cleanup EXIT

# Trap for specific signals
handle_interrupt() {
    echo "Script interrupted by user"
    cleanup
    exit 130
}
trap handle_interrupt INT TERM
```

**Understanding Exit Codes:**

Every command in Unix returns an exit code (also called status code or return code). Zero means success, and any non-zero value indicates failure. The special variable `$?` holds the exit code of the last command. By checking this, you can determine whether operations succeeded and take appropriate action.

**The Power of set Options:**

The `set -e` option tells bash to exit immediately if any command fails. This prevents cascading errors where one failure causes subsequent commands to operate on incorrect state. The `set -u` option treats undefined variables as errors, catching typos and logic errors early. The `set -o pipefail` option ensures that pipeline failures are detected even if the final command succeeds.

---

### Practical Script Example: Backup Automation

Let's combine everything into a real-world backup script that demonstrates professional scripting practices:

```bash
#!/bin/bash
###############################################################################
# Backup Script - Automated directory backup with rotation
# Author: Wan Mohamad Hanis bin Wan Hassan
# Usage: ./backup.sh SOURCE_DIR DEST_DIR [RETENTION_DAYS]
###############################################################################

set -euo pipefail

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# Default values
readonly RETENTION_DAYS=${3:-7}
readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Function: Print colored messages
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Function: Validate inputs
validate_inputs() {
    if [ $# -lt 2 ]; then
        log_error "Usage: $0 SOURCE_DIR DEST_DIR [RETENTION_DAYS]"
        exit 1
    fi
    
    if [ ! -d "$1" ]; then
        log_error "Source directory does not exist: $1"
        exit 1
    fi
    
    if [ ! -d "$2" ]; then
        log_warn "Destination directory does not exist: $2"
        log_info "Creating destination directory..."
        mkdir -p "$2"
    fi
}

# Function: Calculate directory size
get_directory_size() {
    du -sh "$1" | cut -f1
}

# Function: Create backup
create_backup() {
    local source=$1
    local dest=$2
    local backup_name="backup_${TIMESTAMP}.tar.gz"
    local backup_path="${dest}/${backup_name}"
    
    log_info "Starting backup of $source"
    log_info "Source size: $(get_directory_size "$source")"
    
    if tar -czf "$backup_path" -C "$(dirname "$source")" "$(basename "$source")"; then
        log_info "Backup created successfully: $backup_path"
        log_info "Backup size: $(get_directory_size "$backup_path")"
        return 0
    else
        log_error "Backup creation failed"
        return 1
    fi
}

# Function: Remove old backups
cleanup_old_backups() {
    local dest=$1
    local retention=$2
    
    log_info "Cleaning up backups older than $retention days"
    
    local removed_count=0
    while IFS= read -r old_backup; do
        rm -f "$old_backup"
        log_info "Removed old backup: $(basename "$old_backup")"
        removed_count=$((removed_count + 1))
    done < <(find "$dest" -name "backup_*.tar.gz" -mtime +$retention)
    
    if [ $removed_count -eq 0 ]; then
        log_info "No old backups to remove"
    else
        log_info "Removed $removed_count old backup(s)"
    fi
}

# Function: Generate backup report
generate_report() {
    local dest=$1
    
    log_info "=== Backup Report ==="
    log_info "Total backups: $(find "$dest" -name "backup_*.tar.gz" | wc -l)"
    log_info "Total size: $(du -sh "$dest" | cut -f1)"
    log_info "Latest backup: $(ls -t "$dest"/backup_*.tar.gz | head -1)"
}

# Main execution
main() {
    local source_dir=$1
    local dest_dir=$2
    
    log_info "Backup script started"
    validate_inputs "$@"
    
    if create_backup "$source_dir" "$dest_dir"; then
        cleanup_old_backups "$dest_dir" "$RETENTION_DAYS"
        generate_report "$dest_dir"
        log_info "Backup script completed successfully"
        exit 0
    else
        log_error "Backup script failed"
        exit 1
    fi
}

# Execute main function with all script arguments
main "$@"
```

**Understanding This Professional Script:**

This script demonstrates enterprise-grade practices. Notice how it starts with a clear header documenting its purpose, author, and usage. The `set -euo pipefail` ensures the script fails fast on errors. Constants are declared with `readonly` to prevent accidental modification. Functions have single responsibilities and descriptive names. Color-coded logging makes output easy to scan. Input validation prevents the script from running with bad parameters. The cleanup function ensures old backups don't consume infinite disk space.

---

## 🎯 Officer Training Complete

You've successfully completed Officer Training and developed intermediate-level command-line proficiency. You can now manage processes like a professional system administrator, understand network operations and troubleshoot connectivity issues, and write shell scripts that automate complex workflows.

**Skills You've Mastered:**

Process management gives you control over running programs, letting you start, stop, prioritize, and monitor them. Network operations enable you to diagnose connectivity problems, analyze traffic, and configure network settings. Shell scripting transforms you from a command user into an automation architect capable of building sophisticated tools.

**The Integration of Knowledge:**

Notice how these skills interconnect. When you write scripts to automate system administration tasks, you're combining file operations from Boot Camp with process management and networking from Officer Training. This integration is where real power emerges. A script that backs up files, monitors server health, and sends network alerts combines every skill you've learned so far.

**Professional Growth Path:**

You're now equipped for real-world system administration tasks. You can maintain servers, automate routine operations, troubleshoot system issues, and write scripts that save hours of manual work. Companies pay well for these skills because they directly impact operational efficiency and reliability.

**What's Next:**

You're ready for Special Operations, where you'll learn advanced techniques for performance optimization, sophisticated networking, and complex automation. The foundation you've built here makes those advanced topics accessible. Remember that mastery comes from application—use these skills in real projects, contribute to open-source infrastructure, and build tools that solve actual problems.

**Continue Your Journey:** [Special Operations Module](../03-special-operations/README.md)

---

**Module Status:** ✅ COMPLETE  
**Skill Level:** Intermediate System Administration  
**Time to Mastery:** 20-30 hours of practice  
**Prerequisites for Next Module:** Comfort with all process, network, and scripting operations

**Author:** Wan Mohamad Hanis bin Wan Hassan  
**Framework:** CLI Sovereign Mastery | MPNS™ Methodology  
**Last Updated:** October 20, 2025
