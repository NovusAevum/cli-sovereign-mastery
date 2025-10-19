#!/bin/bash
###############################################################################
# Project Scaffold Generator
# Purpose: Create multi-language project structures using MPNS methodology
# Author: Wan Mohamad Hanis bin Wan Hassan
# License: MIT
###############################################################################

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS] PROJECT_NAME PROJECT_TYPE

PROJECT_TYPES:
  python      - Python application with virtual environment
  node        - Node.js application with npm
  react       - React frontend application
  flask       - Flask web application
  django      - Django web application
  go          - Go application
  rust        - Rust application
  docker      - Dockerized application
  fullstack   - Full-stack application (frontend + backend)

OPTIONS:
  -g, --git       Initialize git repository
  -h, --help      Show this help message

EXAMPLES:
  $0 my-app python
  $0 -g my-web-app flask
  $0 my-project fullstack

EOF
    exit 1
}

log_step() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

# Parse arguments
INIT_GIT=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -g|--git)
            INIT_GIT=true
            shift
            ;;
        -h|--help)
            show_usage
            ;;
        *)
            if [ -z "$PROJECT_NAME" ]; then
                PROJECT_NAME="$1"
            elif [ -z "$PROJECT_TYPE" ]; then
                PROJECT_TYPE="$1"
            fi
            shift
            ;;
    esac
done

# Validate arguments
if [ -z "$PROJECT_NAME" ] || [ -z "$PROJECT_TYPE" ]; then
    echo "Error: PROJECT_NAME and PROJECT_TYPE required"
    show_usage
fi

# Check if project already exists
if [ -d "$PROJECT_NAME" ]; then
    echo "Error: Directory '$PROJECT_NAME' already exists"
    exit 1
fi

log_step "Creating project: $PROJECT_NAME (Type: $PROJECT_TYPE)"

# MPNS: M - Mkdir
mkdir -p "$PROJECT_NAME"
cd "$PROJECT_NAME"
log_success "Project directory created"

# Project type specific scaffolding
case "$PROJECT_TYPE" in
    python)
        log_step "Setting up Python project structure"
        mkdir -p src tests docs
        
        # Create virtual environment
        python3 -m venv venv
        
        # Create requirements.txt
        cat > requirements.txt << 'EOF'
# Core dependencies
pytest>=7.4.0
black>=23.7.0
flake8>=6.1.0
mypy>=1.5.0
EOF
        
        # Create main.py
        cat > src/main.py << 'EOF'
#!/usr/bin/env python3
"""Main application entry point."""

def main():
    """Execute main application logic."""
    print("Hello from CLI Sovereign Mastery!")

if __name__ == "__main__":
    main()
EOF
        
        # Create test file
        cat > tests/test_main.py << 'EOF'
"""Tests for main module."""
import pytest
from src.main import main

def test_main():
    """Test main function."""
    main()  # Should not raise
EOF
        
        # Create README
        cat > README.md << EOF
# $PROJECT_NAME

Python application created with CLI Sovereign Mastery framework.

## Setup

\`\`\`bash
# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run application
python src/main.py

# Run tests
pytest tests/
\`\`\`

## Project Structure

\`\`\`
$PROJECT_NAME/
├── src/           # Source code
├── tests/         # Test files
├── docs/          # Documentation
├── venv/          # Virtual environment
└── requirements.txt
\`\`\`
EOF
        
        log_success "Python project structure created"
        ;;
        
    node)
        log_step "Setting up Node.js project structure"
        mkdir -p src tests docs
        
        # Initialize npm
        npm init -y > /dev/null 2>&1
        
        # Update package.json
        cat > package.json << EOF
{
  "name": "$PROJECT_NAME",
  "version": "1.0.0",
  "description": "Node.js application created with CLI Sovereign Mastery",
  "main": "src/index.js",
  "scripts": {
    "start": "node src/index.js",
    "dev": "nodemon src/index.js",
    "test": "jest"
  },
  "keywords": [],
  "author": "Wan Mohamad Hanis",
  "license": "MIT",
  "devDependencies": {
    "jest": "^29.0.0",
    "nodemon": "^3.0.0"
  }
}
EOF
        
        # Create main file
        cat > src/index.js << 'EOF'
#!/usr/bin/env node
/**
 * Main application entry point
 */

function main() {
    console.log('Hello from CLI Sovereign Mastery!');
}

if (require.main === module) {
    main();
}

module.exports = { main };
EOF
        
        # Create test file
        cat > tests/index.test.js << 'EOF'
const { main } = require('../src/index');

describe('Main', () => {
    test('should execute without error', () => {
        expect(() => main()).not.toThrow();
    });
});
EOF
        
        log_success "Node.js project structure created"
        ;;
        
    flask)
        log_step "Setting up Flask project structure"
        mkdir -p app/{templates,static/{css,js},models,routes} tests
        
        # Create requirements
        cat > requirements.txt << 'EOF'
Flask>=2.3.0
python-dotenv>=1.0.0
pytest>=7.4.0
EOF
        
        # Create app/__init__.py
        cat > app/__init__.py << 'EOF'
"""Flask application factory."""
from flask import Flask

def create_app():
    """Create and configure Flask application."""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'
    
    from app.routes import main
    app.register_blueprint(main.bp)
    
    return app
EOF
        
        # Create routes
        mkdir -p app/routes
        cat > app/routes/main.py << 'EOF'
"""Main application routes."""
from flask import Blueprint, render_template

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    """Home page."""
    return render_template('index.html')
EOF
        
        # Create template
        cat > app/templates/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CLI Sovereign Mastery</title>
</head>
<body>
    <h1>Hello from Flask!</h1>
    <p>Created with CLI Sovereign Mastery framework</p>
</body>
</html>
EOF
        
        # Create run script
        cat > run.py << 'EOF'
#!/usr/bin/env python3
"""Development server entry point."""
from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
EOF
        
        chmod +x run.py
        log_success "Flask project structure created"
        ;;
        
    docker)
        log_step "Setting up Dockerized project structure"
        mkdir -p app docker/{nginx,postgres}
        
        # Create Dockerfile
        cat > Dockerfile << 'EOF'
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "app/main.py"]
EOF
        
        # Create docker-compose.yml
        cat > docker-compose.yml << EOF
version: '3.8'

services:
  app:
    build: .
    container_name: ${PROJECT_NAME}_app
    ports:
      - "8000:8000"
    volumes:
      - ./app:/app
    environment:
      - ENVIRONMENT=development
    depends_on:
      - db
    networks:
      - app-network

  db:
    image: postgres:15-alpine
    container_name: ${PROJECT_NAME}_db
    environment:
      POSTGRES_DB: appdb
      POSTGRES_USER: appuser
      POSTGRES_PASSWORD: changeme
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - app-network

volumes:
  postgres_data:

networks:
  app-network:
    driver: bridge
EOF
        
        # Create .dockerignore
        cat > .dockerignore << 'EOF'
__pycache__
*.pyc
*.pyo
*.pyd
.Python
venv/
.git
.gitignore
README.md
.env
EOF
        
        log_success "Docker project structure created"
        ;;
        
    *)
        echo "Error: Unknown project type: $PROJECT_TYPE"
        show_usage
        ;;
esac

# Create common files
log_step "Creating common project files"

# .gitignore
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
venv/
ENV/
.env

# Node
node_modules/
npm-debug.log
yarn-error.log

# IDEs
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Build artifacts
dist/
build/
*.egg-info/
EOF

log_success "Common files created"

# Initialize git if requested
if [ "$INIT_GIT" = true ]; then
    log_step "Initializing git repository"
    git init > /dev/null 2>&1
    git add .
    git commit -m "Initial commit: $PROJECT_TYPE project scaffold" > /dev/null 2>&1
    log_success "Git repository initialized"
fi

# Print summary
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Project created successfully!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Project: $PROJECT_NAME"
echo "Type: $PROJECT_TYPE"
echo "Location: $(pwd)"
echo ""
echo "Next steps:"
echo "  cd $PROJECT_NAME"

case "$PROJECT_TYPE" in
    python|flask)
        echo "  source venv/bin/activate"
        echo "  pip install -r requirements.txt"
        ;;
    node)
        echo "  npm install"
        echo "  npm start"
        ;;
    docker)
        echo "  docker-compose up --build"
        ;;
esac

echo ""
echo "Happy coding! 🚀"
