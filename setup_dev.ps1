# Create Python virtual environment
python -m venv venv
if (-not $?) { Write-Host "Failed to create virtualenv. Try running PowerShell as Administrator."; exit 1 }

# Activate virtual environment
.\venv\Scripts\Activate.ps1
if (-not $?) { Write-Host "Failed to activate virtualenv"; exit 1 }

# Upgrade pip
pip install --upgrade pip
if (-not $?) { Write-Host "Failed to upgrade pip"; exit 1 }

# Install Python dependencies
pip install -r requirements.txt
if (-not $?) { Write-Host "Failed to install Python dependencies"; exit 1 }

# Install frontend dependencies
cd frontend
if (-not $?) { Write-Host "Failed to cd into frontend"; exit 1 }
npm install
if (-not $?) { Write-Host "Failed to install frontend dependencies"; exit 1 }
cd ..

# Create .env file if it doesn't exist
if (-not (Test-Path .env)) {
    Write-Host "Creating .env file..."
    @"
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
"@ | Out-File -FilePath .env -Encoding UTF8
}

Write-Host "`nDevelopment environment setup complete!"
Write-Host "`nTo start the backend:"
Write-Host "1. Open a new PowerShell window"
Write-Host "2. Navigate to the project directory: cd $PWD"
Write-Host "3. Activate the virtual environment: .\venv\Scripts\Activate.ps1"
Write-Host "4. Run: uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000"
Write-Host "`nTo start the frontend:"
Write-Host "1. Open another PowerShell window"
Write-Host "2. Navigate to the frontend directory: cd $PWD\frontend"
Write-Host "3. Run: npm start" 