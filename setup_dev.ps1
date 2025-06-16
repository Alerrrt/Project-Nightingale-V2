# Create Python virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Install Python dependencies
pip install -r requirements.txt

# Install frontend dependencies
cd frontend
npm install
cd ..

# Create .env file if it doesn't exist
if (-not (Test-Path .env)) {
    Write-Host "Creating .env file..."
    @"
# Backend settings
BACKEND_HOST=localhost
BACKEND_PORT=8000
DEBUG=True

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