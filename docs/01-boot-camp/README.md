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

**Let me know your priority and I'll proceed with precision.**v1

# Defense: Implement network segmentation to limit SMB enumeration scope
```

---

## 🔄 Part 4: File Manipulation Operations

Now that you understand how to view and navigate files, let's learn how to manipulate them safely and effectively.

### Moving and Renaming Files

The `mv` command serves a dual purpose in Unix systems. It can move files to different locations, and it can also rename files. This dual functionality comes from the Unix philosophy that renaming is essentially moving a file to a new name in the same location.

**Basic Move Operations:**
```bash
# Rename a file (most common use)
mv oldname.txt newname.txt

# Move file to different directory
mv document.txt /home/user/Documents/

# Move and rename simultaneously
mv report.txt /backup/monthly_report_2025.txt

# Move multiple files to directory
mv file1.txt file2.txt file3.txt /destination/
```

**Understanding the Safety Implications:**

The `mv` command can be dangerous because it will silently overwrite existing files by default. This means if you move `file1.txt` to a location where `file1.txt` already exists, the original will be replaced without warning. Let me show you how to work safely:

```bash
# Interactive mode (ask before overwriting)
mv -i source.txt destination.txt
# You'll see: overwrite 'destination.txt'? (y/n)

# Never overwrite existing files
mv -n source.txt destination.txt

# Only overwrite if source is newer
mv -u source.txt destination.txt

# Verbose mode (see what's happening)
mv -v source.txt destination.txt
```

**Real-World Scenario:**

Imagine you're organizing project files and need to archive completed work. Here's a safe, systematic approach:

```bash
# Step 1: Create archive directory with timestamp
mkdir -p ~/archive/project_$(date +%Y%m%d)

# Step 2: Move completed files interactively
mv -i ~/project/completed_*.txt ~/archive/project_$(date +%Y%m%d)/

# Step 3: Verify the move worked
ls ~/archive/project_$(date +%Y%m%d)/
```

**Common Mistakes and How to Avoid Them:**

The most common mistake beginners make is forgetting that `mv` can overwrite files. Always use `-i` (interactive mode) when learning, or `-n` (no-clobber) when writing scripts. Another mistake is trying to move directories that contain important system files—always double-check your paths before pressing Enter.

---

### Deleting Files Safely

The `rm` command (remove) is one of the most powerful and potentially dangerous commands in Unix. Unlike graphical interfaces where deleted files go to a trash bin, `rm` permanently deletes files immediately. There is no undo button. Let's learn to use it safely.

**Basic Deletion Operations:**
```bash
# Delete a single file
rm filename.txt

# Delete multiple files
rm file1.txt file2.txt file3.txt

# Delete with pattern matching
rm *.tmp           # All files ending in .tmp
rm test_*          # All files starting with test_

# Delete empty directory
rmdir empty_folder/

# Delete directory and contents (DANGEROUS!)
rm -r directory/
```

**The Critical Importance of Safety:**

Before we go further, understand this: **there is no trash bin with `rm`**. Once you delete something, it's gone. Professional system administrators follow strict protocols to avoid disasters. Here are the safety measures you should always follow:

```bash
# ALWAYS use interactive mode when learning
rm -i filename.txt
# Prompt: remove regular file 'filename.txt'? (y/n)

# List files first, then delete
ls *.log           # See what matches
rm -i *.log        # Then delete safely

# Verbose mode to see what's being deleted
rm -v file1.txt file2.txt
# Output: removed 'file1.txt'
#         removed 'file2.txt'

# Combine for maximum safety
rm -iv *.tmp       # Interactive + verbose
```

**The Golden Rule of Deletion:**

Before running any `rm` command, replace `rm` with `ls` first to preview what will be affected. For example, if you plan to run `rm *.txt`, first run `ls *.txt` to see exactly which files will be deleted. This simple habit has saved countless professionals from catastrophic mistakes.

**Understanding Recursive Deletion:**

When you need to delete directories and their contents, you use the recursive flag `-r`. This is extremely powerful and must be used with great care:

```bash
# Delete directory and everything inside
rm -r project_old/

# SAFER: Delete with confirmation for each file
rm -ri project_old/

# SAFEST for beginners: Use interactive mode always
rm -riv project_old/
```

**Real-World Safety Procedure:**

Let's walk through a professional workflow for cleaning up old project files:

```bash
# Step 1: Navigate to parent directory
cd ~/projects

# Step 2: List what you plan to delete
ls -la old_project/

# Step 3: If you're sure, create a backup first
cp -r old_project/ old_project_backup_$(date +%Y%m%d)

# Step 4: Now delete with confirmation
rm -riv old_project/

# Step 5: Verify deletion
ls -la | grep old_project
```

**A Word of Warning:**

You may encounter the infamous command `rm -rf /` in internet discussions. This command attempts to delete your entire system. Modern systems have protections against this, but older systems do not. Never run any command you don't understand, especially if it contains `rm -rf`. When in doubt, ask an experienced colleague or search for the command's purpose before executing it.

---

### Understanding File Permissions

Unix file permissions are fundamental to system security. Every file and directory has permissions that control who can read, write, or execute them. Understanding permissions is essential not just for basic operations, but as foundation for security practices you'll learn in advanced modules.

**The Permission Structure:**

When you run `ls -l`, you see permissions displayed like this: `-rw-r--r--`. Let's decode this:

```
-rw-r--r--  1  hanis  staff  2048  Oct 19 10:30  document.txt
│││││││││││
│└┴┴┴┴┴┴┴┴┴─ Permissions
└─────────── File type (- = file, d = directory, l = link)

Breaking down the permissions:
rw-  r--  r--
│    │    │
│    │    └─ Others (everyone else)
│    └────── Group
└─────────── Owner (you)

Each section has three positions:
r = read permission (4)
w = write permission (2)
x = execute permission (1)
- = no permission (0)
```

**Understanding What Each Permission Means:**

For files, the permissions work like this. Read permission (`r`) allows you to view the file's contents using commands like `cat` or `less`. Write permission (`w`) lets you modify or delete the file. Execute permission (`x`) allows you to run the file as a program, which is essential for scripts and compiled programs.

For directories, permissions work slightly differently. Read permission (`r`) lets you list the directory's contents with `ls`. Write permission (`w`) allows you to create, delete, or rename files within the directory. Execute permission (`x`) lets you enter the directory with `cd` and access files inside it. Interestingly, you can have execute permission on a directory without read permission, allowing you to access files if you know their names, but not list what's there.

**Changing Permissions with chmod:**

The `chmod` command changes file permissions. You can use either numeric or symbolic notation. Let's start with the more intuitive symbolic method:

```bash
# Add execute permission for owner
chmod u+x script.sh

# Remove write permission for group
chmod g-w document.txt

# Add read permission for others
chmod o+r public_file.txt

# Set exact permissions for everyone
chmod a=r public_readonly.txt

# Combine multiple changes
chmod u+x,g+r,o-w complex_file.sh
```

The letters mean: `u` (user/owner), `g` (group), `o` (others), `a` (all). The operators are: `+` (add permission), `-` (remove permission), `=` (set exact permission).

**Numeric Permission Method:**

Professional system administrators often use numeric notation because it's more concise. Each permission has a numeric value (read=4, write=2, execute=1), and you add them together:

```bash
# 755 = rwxr-xr-x (owner: all, group: read+execute, others: read+execute)
chmod 755 script.sh

# 644 = rw-r--r-- (owner: read+write, group: read, others: read)
chmod 644 document.txt

# 600 = rw------- (owner: read+write, nobody else can access)
chmod 600 private_key.pem

# 777 = rwxrwxrwx (everyone can do everything - AVOID THIS!)
chmod 777 script.sh  # Dangerous! Never use unless absolutely necessary
```

**Common Permission Patterns and Their Uses:**

Understanding common permission patterns helps you set appropriate security. For executable scripts, use `755` (`rwxr-xr-x`) which allows you to run them while preventing others from modifying them. For configuration files, use `644` (`rw-r--r--`) which lets you edit them but others can only read. For sensitive files like SSH keys, use `600` (`rw-------`) ensuring only you can access them—SSH actually requires this and won't work with looser permissions.

**Changing Ownership:**

Sometimes you need to change who owns a file. This requires elevated privileges:

```bash
# Change owner (requires sudo)
sudo chown username file.txt

# Change owner and group
sudo chown username:groupname file.txt

# Change owner recursively
sudo chown -R username directory/

# Change only group
sudo chgrp groupname file.txt
```

**Real-World Permission Scenario:**

Let's walk through setting up a shared project directory where team members can collaborate:

```bash
# Create shared directory
mkdir ~/team_project

# Set permissions so group can write
chmod 775 ~/team_project

# Change group to team
sudo chgrp developers ~/team_project

# Set default permissions for new files
chmod g+s ~/team_project  # Set GID bit

# Now all team members can collaborate safely
```

---

## 📦 Part 5: File Compression and Archives

Working with compressed archives is a daily task for system administrators and developers. Understanding how to create, extract, and manage archives efficiently is essential for backup operations, software distribution, and file transfers.

### Working with tar Archives

The `tar` command (tape archive) is the standard Unix tool for creating archives. Despite its name referring to tape drives, it's used for all kinds of archiving today. Let's understand how it works:

```bash
# Create archive (c=create, v=verbose, f=file)
tar -cvf archive.tar directory/

# Extract archive (x=extract, v=verbose, f=file)
tar -xvf archive.tar

# List contents without extracting (t=list)
tar -tvf archive.tar

# Create compressed archive with gzip (z=gzip)
tar -czf archive.tar.gz directory/

# Create compressed archive with bzip2 (j=bzip2, better compression)
tar -cjf archive.tar.bz2 directory/

# Extract compressed archives
tar -xzf archive.tar.gz   # gzip
tar -xjf archive.tar.bz2  # bzip2
tar -xJf archive.tar.xz   # xz (highest compression)

# Extract to specific directory
tar -xzf archive.tar.gz -C /destination/path/
```

**Understanding Compression Trade-offs:**

Different compression algorithms offer different balances of speed versus compression ratio. Gzip (`.tar.gz` or `.tgz`) is fast and provides good compression for most uses. Bzip2 (`.tar.bz2`) is slower but achieves better compression, making it ideal for long-term storage. XZ (`.tar.xz`) provides the best compression but is the slowest, best used when minimizing file size is critical and you have time to spare.

**Practical Archiving Strategies:**

When creating archives for backup, always include verbose mode (`-v`) so you can see what's being archived. This helps catch mistakes before they become problems. For large directories, consider excluding unnecessary files:

```bash
# Exclude specific patterns
tar -czf backup.tar.gz --exclude='*.log' --exclude='tmp/*' project/

# Preserve permissions and ownership
tar -czpf backup.tar.gz directory/  # p=preserve permissions
```

---

## 🔍 Part 6: Finding Files and Content

As you work with larger file systems, finding specific files becomes crucial. The `find` command is one of the most powerful tools in Unix, capable of searching based on names, types, sizes, dates, and even executing commands on the results.

### Mastering the find Command

The `find` command searches through directory trees, testing each file against conditions you specify. Let's build understanding from simple to complex:

```bash
# Find by name
find /path -name "filename.txt"

# Case-insensitive search
find /path -iname "README"

# Find all PDF files
find /path -name "*.pdf"

# Find directories only
find /path -type d -name "config"

# Find files only
find /path -type f -name "*.log"
```

**Finding by Size:**

You can search for files based on their size, which is invaluable for finding what's consuming disk space:

```bash
# Files larger than 100MB
find /path -type f -size +100M

# Files smaller than 1KB
find /path -type f -size -1k

# Files exactly 1GB
find /path -type f -size 1G

# Find large files and show their sizes
find /path -type f -size +100M -exec ls -lh {} \;
```

**Finding by Time:**

Files have three timestamps in Unix systems. Understanding these helps you track down recently modified or accessed files:

```bash
# Modified in last 7 days
find /path -mtime -7

# Not modified in last 30 days
find /path -mtime +30

# Accessed in last 24 hours
find /path -atime -1

# Changed status in last hour
find /path -ctime -1
```

**Combining find with Actions:**

The real power of `find` comes from executing commands on the results. This lets you process multiple files automatically:

```bash
# Delete all .tmp files
find /path -name "*.tmp" -delete

# Make all .sh files executable
find /path -name "*.sh" -exec chmod +x {} \;

# Copy all .conf files to backup
find /path -name "*.conf" -exec cp {} /backup/ \;

# Show details of large files
find /path -size +100M -exec ls -lh {} \;

# Count lines in all Python files
find /path -name "*.py" -exec wc -l {} +
```

---

## 📝 Part 7: Basic Text Processing

Text processing is fundamental to Unix philosophy. Let's learn the essential tools for viewing and manipulating text files.

### Counting with wc

The `wc` (word count) command counts lines, words, and characters:

```bash
# Count everything
wc file.txt          # Shows: lines words bytes filename

# Count only lines
wc -l file.txt

# Count only words
wc -w file.txt

# Count only characters
wc -m file.txt

# Multiple files
wc -l *.txt          # Shows count for each file plus total
```

### Sorting Data

The `sort` command arranges lines of text in order:

```bash
# Alphabetical sort
sort file.txt

# Numeric sort
sort -n numbers.txt

# Reverse sort
sort -r file.txt

# Sort by specific column
sort -k2 data.txt    # Sort by 2nd column

# Remove duplicates while sorting
sort -u file.txt

# Case-insensitive sort
sort -f file.txt
```

### Finding Unique Lines

The `uniq` command removes or reports duplicate lines:

```bash
# Remove adjacent duplicates (requires sorted input)
sort file.txt | uniq

# Count occurrences
sort file.txt | uniq -c

# Show only duplicates
sort file.txt | uniq -d

# Show only unique lines
sort file.txt | uniq -u
```

---

## 🎓 Boot Camp Graduation

Congratulations! You've completed the Boot Camp module and built a solid foundation in command-line operations. You now understand how to navigate file systems with confidence, create and manipulate files safely, manage permissions for security, work with archives for backups, find files efficiently, and process text data.

**Key Principles to Remember:**

Always verify your location with `pwd` before running destructive operations. The terminal has no undo button, so think before you execute, especially with `rm` commands. Use interactive modes (`-i` flag) when learning to prevent accidents. Test commands with `ls` before using `rm` to see what will be affected.

**Your MPNS Mastery:**

You've internalized the MPNS methodology through repetition. Creating structure with `mkdir`, positioning yourself with `cd`, crafting content with editors, and executing operations has become muscle memory. This pattern will serve you throughout your terminal career.

**What's Next:**

You're now ready for Officer Training, where you'll learn process management, networking operations, and shell scripting. The foundation you've built here makes those advanced topics accessible. Remember that mastery comes from practice—spend time working with these commands in real projects to solidify your understanding.

**Continue Your Journey:** [Officer Training Module](../02-officer-training/README.md)

---

**Module Status:** ✅ COMPLETE  
**Skill Level:** Beginner to Intermediate Foundation  
**Time to Mastery:** 10-15 hours of practice  
**Prerequisites for Next Module:** Comfort with all commands covered here

**Author:** Wan Mohamad Hanis bin Wan Hassan  
**Framework:** CLI Sovereign Mastery | MPNS™ Methodology  
**Last Updated:** October 20, 2025