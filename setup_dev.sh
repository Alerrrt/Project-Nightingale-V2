#!/bin/bash

# Create Python virtual environment
python -m venv venv || { echo "Failed to create virtualenv"; exit 1; }

# Activate virtual environment
if [[ "$OSTYPE" == "msys" ]]; then
    source venv/Scripts/activate
else
    source venv/bin/activate
fi

# Upgrade pip
pip install --upgrade pip || { echo "Failed to upgrade pip"; exit 1; }

# Install Python dependencies
pip install -r requirements.txt || { echo "Failed to install Python dependencies"; exit 1; }

# Install frontend dependencies
cd frontend || { echo "Failed to cd into frontend"; exit 1; }
npm install || { echo "Failed to install frontend dependencies"; exit 1; }
cd ..

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "Creating .env file..."
    cat > .env << EOL
# Backend settings
BACKEND_HOST=0.0.0.0           # Host for backend server
BACKEND_PORT=8000              # Port for backend server
DEBUG=True                     # Enable debug mode
SECRET_KEY=your-secret-key-here # Secret key for JWT and security

# CORS settings
CORS_ORIGINS=*

# Scanner settings
MAX_CONCURRENT_SCANS=5
SCAN_TIMEOUT=3600
MAX_RETRIES=3
SCANNER_DEFAULT_TIMEOUT=30
SCANNER_MAX_RETRIES=3
SCANNER_BATCH_SIZE=5

# Resource limits
MAX_CPU_PERCENT=80
MAX_MEMORY_MB=1024
MAX_NETWORK_CONNECTIONS=1000

# Frontend settings
REACT_APP_API_URL=http://localhost:8000
EOL
fi

echo "Development environment setup complete!"
echo "To start the backend:"
echo "1. Activate the virtual environment: source venv/bin/activate (or venv\\Scripts\\activate on Windows)"
echo "2. Run: uvicorn backend.main:app --reload"
echo ""
echo "To start the frontend:"
echo "1. cd frontend"
echo "2. npm start" 
