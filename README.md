# Security Scanner

A modern, scalable security scanning platform with real-time monitoring and advanced error handling.

## Features

- **Advanced Security Scanning**: Comprehensive security scanning capabilities with support for multiple scanner types
- **Real-time Monitoring**: Live updates and progress tracking for ongoing scans
- **Resource Management**: Intelligent resource allocation and monitoring
- **Error Recovery**: Circuit breaker pattern for graceful error handling
- **Structured Logging**: JSON-formatted logs with detailed context
- **Metrics Collection**: Comprehensive metrics for monitoring and analysis
- **Plugin System**: Extensible plugin architecture for custom scanners
- **API-First Design**: RESTful API with OpenAPI documentation

## Architecture

The system is built with a modular architecture:

- **Scanner Engine**: Core scanning functionality with resource management
- **Plugin System**: Extensible plugin architecture for custom scanners
- **API Layer**: FastAPI-based REST API with real-time updates
- **Monitoring**: Resource monitoring and metrics collection
- **Error Handling**: Circuit breaker pattern for graceful failure handling
- **Logging**: Structured logging with context and metrics

## Getting Started

### Prerequisites

- Python 3.8+
- PostgreSQL 12+
- Redis (optional, for caching)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/security-scanner.git
cd security-scanner
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Initialize the database:
```bash
alembic upgrade head
```

### Running the Application

1. Start the API server:
```bash
uvicorn backend.main:app --reload
```

2. Access the API documentation:
```
http://localhost:8000/docs
```

## API Usage

### Starting a Scan

```python
import requests

response = requests.post(
    "http://localhost:8000/api/scans/start",
    json={
        "target": "example.com",
        "scan_type": "vulnerability",
        "options": {
            "intensity": "high",
            "timeout": 300
        }
    }
)

scan_id = response.json()["scan_id"]
```

### Checking Scan Status

```python
status = requests.get(f"http://localhost:8000/api/scans/status/{scan_id}")
print(status.json())
```

### Getting Real-time Updates

```python
import websockets

async with websockets.connect("ws://localhost:8000/api/realtime/updates") as ws:
    while True:
        update = await ws.recv()
        print(update)
```

## Development

### Running Tests

```bash
pytest
```

### Code Style

```bash
black .
isort .
flake8
mypy .
```

## Monitoring

The application includes comprehensive monitoring:

- **Resource Monitoring**: CPU, memory, and network usage
- **Circuit Breakers**: Automatic error recovery
- **Structured Logging**: JSON-formatted logs with context
- **Metrics**: Prometheus metrics for monitoring

### Logging

Logs are written in JSON format with detailed context:

```json
{
    "timestamp": "2023-11-15T10:30:00Z",
    "level": "INFO",
    "message": "Scan started",
    "scan_id": "scan_123",
    "target": "example.com",
    "scan_type": "vulnerability"
}
```

### Metrics

Metrics are available at `/metrics` endpoint:

- `scanner_total_scans`: Total number of scans
- `scanner_successful_scans`: Number of successful scans
- `scanner_failed_scans`: Number of failed scans
- `scanner_duration_seconds`: Scan duration in seconds
- `resource_cpu_percent`: CPU usage percentage
- `resource_memory_mb`: Memory usage in MB
- `resource_network_connections`: Number of network connections

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

 