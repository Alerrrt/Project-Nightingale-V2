#!/bin/bash

# Create Python virtual environment
python -m venv venv

# Activate virtual environment
if [[ "$OSTYPE" == "msys" ]]; then
    source venv/Scripts/activate
else
    source venv/bin/activate
fi

# Install Python dependencies
pip install -r requirements.txt

# Install frontend dependencies
cd frontend
npm install
cd ..

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "Creating .env file..."
    cat > .env << EOL
# Backend settings
BACKEND_HOST=localhost
BACKEND_PORT=8000
DEBUG=True

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