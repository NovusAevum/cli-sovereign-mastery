
echo ""

# Check cloud CLI tools
print_header "Cloud Platform CLIs"
check_command "aws" "false"
check_command "gcloud" "false"
check_command "az" "false"
check_command "terraform" "false"
echo ""

# Check permissions
print_header "Permissions & Access"
if [ -w "$HOME" ]; then
    echo -e "${GREEN}✓${NC} Home directory is writable"
else
    echo -e "${RED}✗${NC} Home directory is not writable"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi

if groups | grep -q sudo || groups | grep -q wheel || groups | grep -q admin; then
    echo -e "${GREEN}✓${NC} User has sudo/admin privileges"
else
    echo -e "${YELLOW}○${NC} User does not have sudo privileges (some operations will be limited)"
fi

# Check if can execute scripts
TEST_SCRIPT="/tmp/cli_test_$$.sh"
echo "#!/bin/bash" > "$TEST_SCRIPT"
echo "echo 'test'" >> "$TEST_SCRIPT"
chmod +x "$TEST_SCRIPT"
if [ -x "$TEST_SCRIPT" ]; then
    echo -e "${GREEN}✓${NC} Can create and execute scripts"
    rm -f "$TEST_SCRIPT"
else
    echo -e "${RED}✗${NC} Cannot execute scripts"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
    rm -f "$TEST_SCRIPT"
fi
echo ""

# Check network connectivity
print_header "Network Connectivity"
if ping -c 1 8.8.8.8 &> /dev/null; then
    echo -e "${GREEN}✓${NC} Internet connectivity (IPv4)"
else
    echo -e "${RED}✗${NC} No internet connectivity"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi

if curl -s --head https://github.com | head -1 | grep "200" > /dev/null; then
    echo -e "${GREEN}✓${NC} GitHub accessible"
else
    echo -e "${YELLOW}○${NC} GitHub not accessible (may affect some operations)"
fi
echo ""

# Disk space check
print_header "System Resources"
DISK_AVAIL=$(df -h "$HOME" | awk 'NR==2 {print $4}')
echo "Available disk space in $HOME: $DISK_AVAIL"

TOTAL_MEM=$(free -h 2>/dev/null | awk '/^Mem:/ {print $2}' || sysctl hw.memsize 2>/dev/null | awk '{print $2/1024/1024/1024 " GB"}')
if [ ! -z "$TOTAL_MEM" ]; then
    echo "Total memory: $TOTAL_MEM"
fi

LOAD_AVG=$(uptime | awk -F'load average:' '{print $2}')
echo "Load average:$LOAD_AVG"
echo ""

# Final summary
print_header "Summary"
if [ $ISSUES_FOUND -eq 0 ]; then
    echo -e "${GREEN}✓ Environment check passed!${NC}"
    echo -e "${GREEN}✓ System is ready for CLI Sovereign Mastery training${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠ Found $ISSUES_FOUND issue(s)${NC}"
    echo -e "${YELLOW}⚠ Some functionality may be limited${NC}"
    echo ""
    echo "Install missing required tools before proceeding with training."
    exit 1
fi
