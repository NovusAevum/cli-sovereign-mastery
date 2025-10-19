# Contributing to CLI Sovereign Mastery

Thank you for your interest in contributing to this project! This framework thrives on community expertise and real-world scenarios.

## Code of Conduct

### Our Standards

- **Professional Excellence:** Maintain enterprise-grade quality in all contributions
- **Security First:** Never introduce vulnerabilities or insecure patterns
- **Clarity Over Cleverness:** Code should be readable and maintainable
- **Evidence-Based:** Claims must be backed by documentation or testing
- **Respect:** Professional discourse in all interactions

## How to Contribute

### 1. Fork and Clone

```bash
# Fork repository on GitHub
# Then clone your fork
git clone https://github.com/YOUR_USERNAME/cli-sovereign-mastery.git
cd cli-sovereign-mastery
```

### 2. Create Feature Branch

```bash
git checkout -b feature/your-contribution-name
```

### 3. Make Your Changes

Follow the MPNS methodology and existing documentation patterns:

- **Precision:** Every command must be accurate and tested
- **Context:** Explain why, not just what
- **Security:** Include both offensive and defensive perspectives where relevant
- **Cross-Platform:** Note platform differences (Linux/macOS/Windows)

### 4. Test Thoroughly

```bash
# Run environment check
./scripts/env-check.sh

# Test any scripts you've created
./your-script.sh

# Verify documentation renders correctly
```

### 5. Commit with Clear Messages

```bash
git add .
git commit -m "feat: Add advanced SSH tunneling techniques

- Local and remote port forwarding examples
- SOCKS proxy configuration
- Security implications and defense
- Tested on Ubuntu 22.04 and macOS 14"
```

**Commit Message Format:**
- `feat:` New feature or content
- `fix:` Bug fix or correction
- `docs:` Documentation improvements
- `security:` Security-related changes
- `refactor:` Code restructuring
- `test:` Adding or updating tests

### 6. Push and Create Pull Request

```bash
git push origin feature/your-contribution-name
```

Then create a Pull Request on GitHub with:
- Clear description of changes
- Rationale for the contribution
- Testing methodology
- Platform(s) tested on

## Contribution Types

### Highly Valuable

✅ **Real-World Enterprise Scenarios** — Production experiences and lessons learned  
✅ **Security Discoveries** — Vulnerabilities, defense patterns, attack techniques  
✅ **Performance Optimizations** — Benchmarked improvements  
✅ **Automation Scripts** — Production-ready utilities with error handling  
✅ **Cross-Platform Fixes** — Compatibility improvements  

### Welcome

✅ **Documentation Improvements** — Clarity, examples, corrections  
✅ **Additional Examples** — Real use cases with context  
✅ **Tool Integrations** — Modern CLI tools and frameworks  

### Not Accepted

❌ **Toy Examples** — Non-production quality code  
❌ **Insecure Patterns** — Code with known vulnerabilities  
❌ **Untested Content** — Contributions without validation  
❌ **Plagiarism** — Must be original or properly attributed  

## Quality Standards

All contributions must meet these criteria:

### 1. Enterprise Grade

```bash
# ❌ Toy example
rm -rf temp

# ✅ Enterprise grade
if [ -d "temp" ] && [ "$(pwd)" = "/expected/path" ]; then
    rm -rf temp
    echo "Cleaned temp directory"
else
    echo "Error: Invalid context for deletion" >&2
    exit 1
fi
```

### 2. Proper Error Handling

```bash
# ❌ No error handling
mkdir project
cd project

# ✅ With error handling
if mkdir -p project; then
    cd project || exit 1
else
    echo "Failed to create project directory" >&2
    exit 1
fi
```

### 3. Security Reviewed

- No hardcoded credentials
- Input validation where applicable
- Secure defaults
- Warnings for dangerous operations

### 4. Well Documented

```bash
#!/bin/bash
###############################################################################
# Script Name: example-utility.sh
# Purpose: Brief description of what this does
# Author: Your Name
# Date: 2025-01-01
# Usage: ./example-utility.sh [OPTIONS] ARGUMENT
###############################################################################

# Function documentation
# Purpose: Describe what this function does
# Arguments:
#   $1 - First argument description
#   $2 - Second argument description
# Returns:
#   0 on success, 1 on failure
function_name() {
    local arg1="$1"
    local arg2="$2"
    
    # Implementation with comments for complex logic
}
```

### 5. Cross-Platform Awareness

```bash
# Platform-specific code
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS specific
    alias ls='ls -G'
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux specific
    alias ls='ls --color=auto'
fi
```

## Review Process

1. **Automated Checks:** Scripts must pass shellcheck linting
2. **Manual Review:** Maintainer reviews for quality and security
3. **Testing:** Verification across platforms where applicable
4. **Feedback:** Constructive feedback provided for improvements
5. **Merge:** Accepted contributions are merged and credited

## Getting Help

- **Questions:** Open a GitHub Discussion
- **Bugs:** Create an Issue with reproduction steps
- **Security:** Email security@example.com (replace with actual contact)

## Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Credited in relevant documentation sections
- Acknowledged in release notes

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for helping make CLI Sovereign Mastery the definitive command-line framework!**

*Built with discipline. Delivered with precision. Maintained with excellence.*
