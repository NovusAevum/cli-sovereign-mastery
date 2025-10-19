# 🎖️ Boot Camp: Terminal Fundamentals

**Mission Objective:** Establish unshakeable foundation in command-line operations through systematic mastery of core primitives.

**Time Investment:** 10-15 hours over 2 weeks  
**Prerequisites:** Terminal access on Linux, macOS, or Windows (WSL2)  
**Completion Criteria:** Execute all commands from memory without reference, understand security implications of each operation

---

## 🎯 Boot Camp Philosophy

Military boot camp breaks down civilians and rebuilds them as soldiers through repetition, discipline, and muscle memory. This module applies the same principle to terminal mastery.

**Three Pillars of Foundational Mastery:**

1. **Spatial Awareness** — Know where you are in the file system at all times
2. **Operational Precision** — Every command executed with intent and understanding
3. **Risk Management** — Recognize potentially destructive operations before execution

---

## 📍 Part 1: Navigation & Orientation

### The File System Hierarchy

Every Unix-like system follows a standardized directory structure. Understanding this is prerequisite to navigation mastery.

```
/                           # Root (top of file system)
├── bin/                    # Essential user binaries (ls, cat, cp)
├── boot/                   # Boot loader files, kernel
├── dev/                    # Device files (hardware interfaces)
├── etc/                    # System configuration files
├── home/                   # User home directories
│   └── username/           # Your user directory
├── lib/                    # Shared libraries
├── media/                  # Removable media mount points
├── mnt/                    # Temporary mount points
├── opt/                    # Optional software packages
├── proc/                   # Process information (virtual)
├── root/                   # Root user home directory
├── sbin/                   # System binaries (administrative)
├── srv/                    # Service data
├── sys/                    # System information (virtual)
├── tmp/                    # Temporary files (cleared on reboot)
├── usr/                    # User programs and data
│   ├── bin/                # User binaries
│   ├── lib/                # User libraries
│   ├── local/              # Locally installed software
│   └── share/              # Shared data
└── var/                    # Variable data (logs, caches)
    ├── log/                # System logs
    ├── mail/               # Mail spool
    └── www/                # Web server content
```

**Security Note:** Different directories have different permission requirements. `/etc/` requires root for modification. `/tmp/` is world-writable but has sticky bit set (only owner can delete their files).

### Core Navigation Commands

#### `pwd` — Print Working Directory

**Purpose:** Display absolute path of current directory  
**Syntax:** `pwd [OPTIONS]`

**Common Usage:**
```bash
pwd                        # Display current location
pwd -P                     # Display physical path (resolve symlinks)
pwd -L                     # Display logical path (default, show symlinks)
```

**Practical Examples:**
```bash
# Verify location before destructive operation
pwd && rm -rf temp/        # Only proceeds if you're in expected location

# Capture location for later return
ORIGINAL_DIR=$(pwd)
cd /tmp
# Do work...
cd "$ORIGINAL_DIR"         # Return to original location
```

**MPNS Integration:** The "P" (Position) step always begins with awareness. Use `pwd` after every `cd` until it becomes reflexive.

---

#### `cd` — Change Directory

**Purpose:** Navigate to different locations in file system  
**Syntax:** `cd [DIRECTORY]`

**Essential Patterns:**
```bash
cd /path/to/directory      # Absolute path navigation
cd relative/path           # Relative to current location
cd ..                      # Move up one directory level
cd ../..                   # Move up two levels
cd -                       # Return to previous directory (toggle)
cd ~                       # Go to home directory
cd ~/Documents             # Path relative to home
cd                         # No argument = go to home directory
```

**Advanced Techniques:**
```bash
# Directory stack manipulation
pushd /var/log             # Save current dir and move to /var/log
# Do work in /var/log
popd                       # Return to saved directory

# Create and enter directory atomically
mkdir -p project/src && cd $_ # $_ holds last argument of previous command

# Conditional navigation
cd /opt/myapp 2>/dev/null || echo "Directory doesn't exist"
```

**Security Warning:** Always validate directory before executing commands, especially when using variables:
```bash
# DANGEROUS — could execute in wrong location if variable empty
cd $SOME_VAR && rm -rf *

# SAFER — quotes and validation
if [ -d "$SOME_VAR" ]; then
    cd "$SOME_VAR" && rm -rf *
else
    echo "Invalid directory: $SOME_VAR"
    exit 1
fi
```

**Cross-Platform Notes:**
- Linux/macOS: Case-sensitive paths (`Documents` ≠ `documents`)
- Windows (WSL): Access Windows files via `/mnt/c/Users/...`
- Spaces in paths: Use quotes: `cd "My Documents"` or escape: `cd My\ Documents`

---

#### `ls` — List Directory Contents

**Purpose:** Display files and directories with detailed information  
**Syntax:** `ls [OPTIONS] [PATH]`

**Core Patterns:**
```bash
ls                         # Basic listing (files and directories)
ls -l                      # Long format (detailed information)
ls -a                      # Include hidden files (starting with .)
ls -la                     # Combine: long format + hidden files
ls -lh                     # Human-readable sizes (KB, MB, GB)
ls -lt                     # Sort by modification time (newest first)
ls -ltr                    # Sort by time, reverse (oldest first)
ls -lS                     # Sort by size (largest first)
ls -R                      # Recursive (list subdirectories)
```

**Professional Aliases (add to ~/.bashrc or ~/.zshrc):**
```bash
alias ll='ls -alF'         # Detailed list with file type indicators
alias la='ls -A'           # All except . and ..
alias l='ls -CF'           # Column format with type indicators
alias lt='ls -ltr'         # Time sorted, oldest first
alias lsize='ls -lSh'      # Size sorted, human readable
```

**Output Interpretation:**
```bash
$ ls -lh
drwxr-xr-x  5 wmh  staff   160B Oct 19 14:30 project/
-rw-r--r--  1 wmh  staff   2.4K Oct 19 14:25 README.md
-rwxr-xr-x  1 wmh  staff   512B Oct 19 14:20 script.sh*
```

**Breakdown:**
- `d` = directory, `-` = file, `l` = symbolic link
- `rwxr-xr-x` = permissions (owner/group/others)
- `5` = number of hard links
- `wmh` = owner username
- `staff` = group name
- `160B` = size
- `Oct 19 14:30` = last modification time
- `project/` = name (/ indicates directory, * indicates executable)

**Security Reconnaissance (Attacker Perspective):**
```bash
# Find writable directories (privilege escalation opportunity)
find / -type d -writable 2>/dev/null

# Find SUID binaries (potential privilege escalation)
find / -perm -4000 -type f 2>/dev/null

# List recently modified files (detect changes)
find / -mtime -1 -type f 2>/dev/null

# Find files owned by specific user
find / -user www-data -type f 2>/dev/null
```

**Defense Perspective:**
```bash
# Audit file permissions regularly
find /var/www -type f ! -perm 644 -o -type d ! -perm 755

# Monitor unauthorized permission changes
find / -perm -2 ! -type l 2>/dev/null  # World-writable files
```

---

#### `tree` — Visual Directory Structure

**Purpose:** Display directory hierarchy in tree format  
**Installation:** `brew install tree` (macOS) or `apt install tree` (Ubuntu)

**Common Usage:**
```bash
tree                       # Display current directory tree
tree -L 2                  # Limit depth to 2 levels
tree -a                    # Include hidden files
tree -d                    # Directories only
tree -I 'node_modules|.git'  # Ignore patterns
tree -h                    # Human-readable sizes
tree -p                    # Include permissions
```

**Practical Example:**
```bash
$ tree -L 2 -h -I 'node_modules'
.
├── [ 160]  docs
│   ├── [ 160]  boot-camp
│   └── [ 160]  officer-training
├── [2.4K]  README.md
└── [ 160]  scripts
    ├── [512B]  setup.sh
    └── [1.2K]  audit.sh

3 directories, 3 files
```

---

## 📁 Part 2: File Operations

### Creating Files and Directories

#### `mkdir` — Make Directory

**Purpose:** Create directories  
**Syntax:** `mkdir [OPTIONS] DIRECTORY...`

**Core Patterns:**
```bash
mkdir project              # Create single directory
mkdir dir1 dir2 dir3       # Create multiple directories
mkdir -p path/to/nested/dir  # Create parent directories as needed
mkdir -m 755 public_dir    # Create with specific permissions
mkdir -v output            # Verbose output (confirm creation)
```

**MPNS "M" Step — Create with Purpose:**
```bash
# Standard project structure
mkdir -p project/{src,tests,docs,config}

# Result:
# project/
# ├── src/
# ├── tests/
# ├── docs/
# └── config/

# Full application scaffold
mkdir -p app/{frontend/{src,public},backend/{api,db},infra}

# With permissions for shared environments
mkdir -m 775 /shared/project  # Group-writable for collaboration
```

**Security Considerations:**
```bash
# Default permissions: 755 (rwxr-xr-x) minus umask
# Check current umask
umask           # Example output: 0022

# Calculate actual permissions: 777 - 022 = 755
# For secure directories with sensitive data:
mkdir -m 700 ~/.ssh       # Owner-only access
mkdir -m 750 /opt/secure  # Owner full, group read/execute
```

**Error Handling in Scripts:**
```bash
# Enterprise-grade directory creation
create_directory() {
    local dir_path="$1"
    local permissions="${2:-755}"
    
    if [ -z "$dir_path" ]; then
        echo "Error: Directory path required" >&2
        return 1
    fi
    
    if mkdir -p -m "$permissions" "$dir_path" 2>/dev/null; then
        echo "Created: $dir_path (permissions: $permissions)"
        return 0
    else
        echo "Failed to create: $dir_path" >&2
        return 1
    fi
}

# Usage
create_directory "/opt/myapp" "750"
```

---

#### `touch` — Create Empty Files

**Purpose:** Create files or update timestamps  
**Syntax:** `touch [OPTIONS] FILE...`

**Common Usage:**
```bash
touch file.txt             # Create empty file or update timestamp
touch file1.txt file2.txt  # Create multiple files
touch -c file.txt          # Don't create if doesn't exist
touch -t 202510191430.00 file.txt  # Set specific timestamp (YYYYMMDDhhmm.ss)
touch -r reference.txt new.txt     # Match timestamp of reference file
```

**Practical Applications:**
```bash
# Create file structure quickly
touch README.md LICENSE .gitignore

# Create numbered sequence
touch file{1..10}.txt      # Creates file1.txt through file10.txt

# Create with extensions
touch {index,app,config}.js

# Timestamp manipulation (forensics/testing)
touch -t 202501010000.00 old_file.log  # Backdate file
```

**MPNS "N" Step Integration:**
```bash
# Create and immediately edit
touch script.sh && chmod +x script.sh && nano script.sh

# Create with content in one line
touch config.json && echo '{"env":"production"}' > config.json
```

---

#### `nano` / `vi` / `vim` — Text Editors

**Purpose:** Edit files directly in terminal  
**Skill Level:** nano (beginner), vi (intermediate), vim (advanced)

**Nano — Beginner-Friendly Editor:**
```bash
nano filename.txt          # Open or create file
nano +10 filename.txt      # Open at line 10
nano -w filename.txt       # Disable line wrapping
```

**Essential Nano Commands (displayed at bottom of editor):**
- `CTRL+O` — Write (save) file
- `CTRL+X` — Exit editor
- `CTRL+K` — Cut line
- `CTRL+U` — Paste line
- `CTRL+W` — Search
- `CTRL+\` — Replace
- `CTRL+G` — Help

**Vim — Power User Editor:**
```bash
vim filename.txt           # Open file
vim +/pattern file.txt     # Open and search for pattern
vim -R file.txt            # Read-only mode
vimdiff file1 file2        # Compare files side-by-side
```

**Vim Survival Commands:**
```
i          # Enter INSERT mode (start typing)
ESC        # Exit INSERT mode (back to NORMAL mode)
:w         # Write (save)
:q         # Quit
:wq        # Write and quit
:q!        # Quit without saving
dd         # Delete line
yy         # Copy line
p          # Paste
u          # Undo
CTRL+r     # Redo
/pattern   # Search forward
?pattern   # Search backward
:set number # Show line numbers
```

**Enterprise Vim Configuration (~/.vimrc):**
```vim
set number          " Show line numbers
set autoindent      " Auto-indent new lines
set tabstop=4       " Tab width
set shiftwidth=4    " Indent width
set expandtab       " Use spaces instead of tabs
syntax on           " Syntax highlighting
set hlsearch        " Highlight search results
set ignorecase      " Case-insensitive search
set smartcase       " Case-sensitive if caps in search
```

---

### Viewing File Contents

#### `cat` — Concatenate and Display

**Purpose:** Display entire file contents  
**Syntax:** `cat [OPTIONS] FILE...`

**Common Usage:**
```bash
cat file.txt               # Display file
cat file1.txt file2.txt    # Display multiple files
cat -n file.txt            # Show line numbers
cat -b file.txt            # Number non-empty lines only
cat -A file.txt            # Show all special characters
```

**Practical Applications:**
```bash
# Quick file inspection
cat ~/.ssh/config

# Combine files
cat header.txt body.txt footer.txt > complete.txt

# Create file with heredoc
cat > config.txt << EOF
server=localhost
port=8080
EOF

# Append to file
cat >> logfile.txt << EOF
New log entry
EOF
```

**Security Use Cases:**
```bash
# Examine sensitive files (red team)
cat /etc/passwd           # User accounts
cat /etc/shadow           # Password hashes (requires root)
cat ~/.bash_history       # Command history
cat /proc/version         # Kernel version
cat /etc/issue            # System version
```

---

#### `less` / `more` — Paginated Viewing

**Purpose:** View large files page by page  
**Recommendation:** Use `less` (more powerful than `more`)

**Less Commands:**
```bash
less filename.txt          # Open file
less +F filename.txt       # Follow mode (like tail -f)
less +/pattern file.txt    # Start at first match
```

**Navigation Keys:**
```
SPACE      # Next page
b          # Previous page
d          # Half page down
u          # Half page up
g          # Go to beginning
G          # Go to end
/pattern   # Search forward
?pattern   # Search backward
n          # Next search result
N          # Previous search result
q          # Quit
```

**Advanced Usage:**
```bash
# View compressed files directly
less file.gz               # Automatically decompresses

# Multiple file navigation
less file1.txt file2.txt   # Use :n for next, :p for previous

# With line numbers
less -N file.txt

# Case-insensitive search
less -i file.txt
```

---

#### `head` / `tail` — View File Portions

**Purpose:** Display beginning or end of files

**Head — First N Lines:**
```bash
head file.txt              # First 10 lines (default)
head -n 20 file.txt        # First 20 lines
head -n -5 file.txt        # All except last 5 lines
head -c 100 file.txt       # First 100 bytes
```

**Tail — Last N Lines:**
```bash
tail file.txt              # Last 10 lines (default)
tail -n 20 file.txt        # Last 20 lines
tail -n +5 file.txt        # From line 5 to end
tail -f logfile.txt        # Follow mode (live updates)
tail -F logfile.txt        # Follow with retry (if file rotated)
```

**Real-World Scenarios:**
```bash
# Monitor log files in real-time
tail -f /var/log/syslog

# Check recent errors
tail -100 /var/log/apache2/error.log | grep -i error

# Sample large dataset
head -1000 large_dataset.csv > sample.csv

# View middle section
tail -n +100 file.txt | head -n 50  # Lines 100-149
```

---

## 🔄 Part 3: File Manipulation

### Copying Files

#### `cp` — Copy Files and Directories

**Purpose:** Duplicate files and directories  
**Syntax:** `cp [OPTIONS] SOURCE DEST`

**Essential Patterns:**
```bash
cp source.txt dest.txt     # Copy file
cp file.txt /path/to/dir/  # Copy to directory
cp -r dir1/ dir2/          # Copy directory recursively
cp -p file.txt backup/     # Preserve permissions and timestamps
cp -a dir1/ dir2/          # Archive mode (preserve everything)
cp -i file.txt dest.txt    # Interactive (prompt before overwrite)
cp -v file.txt backup/     # Verbose output
cp -u source/ dest/        # Update (only if source is newer)
```

**Advanced Techniques:**
```bash
# Backup with timestamp
cp important.conf important.conf.$(date +%Y%m%d_%H%M%S)

# Copy multiple files to directory
cp file1.txt file2.txt file3.txt /target/dir/

# Copy with pattern matching
cp *.log /backup/logs/

# Preserve structure while copying
cp --parents src/app/module.py /backup/  # Creates /backup/src/app/module.py

# Safe overwrite protection
cp -n source.txt dest.txt  # Never overwrite existing
```

**Security Considerations:**
```bash
# Preserve security contexts (SELinux)
cp --preserve=context file.txt /secure/location/

# Copy without following symlinks (prevent symlink attacks)
cp -P symlink /safe/location/

# Verify copy integrity
cp file.txt backup/ && diff file.txt backup/file.txt
```

**Enterprise Backup Script:**
```bash
#!/bin/bash
# Production-grade file backup

backup_file() {
    local source="$1"
    local backup_dir="${2:-./backups}"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    
    if [ ! -f "$source" ]; then
        echo "Error: Source file not found: $source" >&2
        return 1
    fi
    
    mkdir -p "$backup_dir" || return 1
    
    local filename=$(basename "$source")
    local backup_path="${backup_dir}/${filename}.${timestamp}"
    
    if cp -p "$source" "$backup_path"; then
        echo "Backed up: $source -> $backup_path"
        return 0
    else
        echo "Backup failed: $source" >&2
        return 1
    fi
}

# Usage
backup_file "/etc/nginx/nginx.conf" "/backup/configs"
```

---

**Boot Camp module is now established with enterprise-grade depth. Would you like me to:**

1. Continue with Move/Delete operations and complete Boot Camp?
2. Create the Officer Training (Intermediate) module?
3. Create specialized security operations module?
4. Create automation scripts directory with production utilities?
5. Initialize git and push everything to your GitHub?

**Let me know your priority and I'll proceed with precision.**