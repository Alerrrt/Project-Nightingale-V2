# Project Nightingale V2: A Scalable Security Platform

Project Nightingale V2 is a complete architectural rewrite of the original reconnaissance script. It transforms the tool from a linear Bash script into a robust, scalable, and API-driven platform for automated reconnaissance and vulnerability scanning.

It is designed with a modern microservices architecture to handle multiple concurrent scans, making it the perfect foundation for a future PTaaS (Penetration Testing as a Service) tool.

## The Problem with V1

The original Project Nightingale was an effective automation script, but it had limitations inherent to its design:
*   **Rigidity:** The workflow was hardcoded, making it difficult to customize scans.
*   **Lack of Scalability:** It could only run one scan at a time on a single machine.
*   **No State Management:** It was difficult to track running scans or query past results.
*   **Difficult Integration:** As a script, it was not designed to be integrated into other systems.

## The V2 Solution: A Modern Architecture

This version solves these problems by rebuilding the project as a distributed system with a clear separation of concerns.

### Key Features
*   **API-Driven:** A RESTful API built with **FastAPI** provides a clean, documented interface for all operations.
*   **Asynchronous Scanning:** Uses **Celery** and **Redis** to manage a task queue, allowing for multiple, long-running scans to be executed in the background without blocking the API.
*   **Scalable & Containerized:** Fully containerized with **Docker** and orchestrated with **Docker Compose**. You can scale the number of worker services to handle more jobs.
*   **Targeted OWASP Top 10 Scanning:** Includes built-in logic to run Nuclei templates specifically tagged for OWASP Top 10 vulnerabilities like SSRF, XSS, SQLi, and misconfigurations.
*   **Highly Configurable Scans:** Control scans with parameters like rate-limiting, concurrency, custom headers for authenticated scanning, and severity filters.
*   **Persistent & Structured Data:** Scan results are stored in a **PostgreSQL** database, not temporary files, allowing for historical analysis and powerful reporting.
*   **Reproducible Environment:** All security tools (`subfinder`, `httprobe`, `nuclei`, etc.) are installed within the Docker image, ensuring the environment is identical for everyone.

---

## Architectural Overview

The system is composed of several independent services that communicate with each other.

```
+-----------+        +-----------------+        +---------------+
|           |        |                 |        |               |
|   User    +------->+  FastAPI (API)  +------->+ Redis (Queue) |
|           |        |                 |        |               |
+-----------+        +-------+---------+        +------+--------+
                               |                       |
                               | (Stores/Retrieves     | (Picks up Job)
                               |  Scan Metadata)      |
                               v                       v
                      +--------+--------+     +--------+--------+
                      |                 |     |                 |
                      | PostgreSQL (DB) +<----+  Celery Workers |
                      |                 |     |  (Run Scans)    |
                      +-----------------+     +-----------------+
```

1.  A **User** sends a request to the **FastAPI** endpoint to start a scan.
2.  The API validates the request and pushes a "scan job" onto the **Redis** message queue.
3.  A **Celery Worker** (running in a separate container) picks up the job from the queue.
4.  The Worker executes the scanning logic (running tools like Nuclei), storing all results in the **PostgreSQL** database.
5.  The User can query the API to check the status of the job or retrieve results from the database.

---

## Technology Stack

| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend API** | Python, FastAPI | Handles HTTP requests, provides API docs. |
| **Task Queue** | Celery, Redis | Manages background jobs for asynchronous scanning. |
| **Database** | PostgreSQL | Stores all scan configurations and results. |
| **Containerization** | Docker, Docker Compose | For building, shipping, and running the platform. |
| **Security Tools**| Nuclei, Subfinder, httprobe | Core tools used by the scanning engine. |

---

## Installation & Setup

### Prerequisites
*   [Docker](https://www.docker.com/products/docker-desktop)
*   [Docker Compose](https://docs.docker.com/compose/install/) (Included with Docker Desktop)

### Step-by-Step Guide

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/Alerrrt/Project-Nightingale-v2.git
    cd project-nightingale
    ```

2.  **Configure Environment Variables**
    Create a file named `.env` in the root of the project. This will store your database credentials securely.
    ```bash
    # .env
    POSTGRES_USER=nightingale
    POSTGRES_PASSWORD=your_super_secret_password
    POSTGRES_DB=nightingale_db
    ```
    *You must update your `docker-compose.yml` to use these variables.*
    ```yaml
    # In docker-compose.yml
    services:
      db:
        environment:
          - POSTGRES_USER=${POSTGRES_USER}
          - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
          - POSTGRES_DB=${POSTGRES_DB}
      api:
        environment:
          - DATABASE_URL=postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@db:5432/${POSTGRES_DB}
      worker:
        environment:
          - DATABASE_URL=postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@db:5432/${POSTGRES_DB}
    ```

3.  **Build and Run the Platform**
    This single command will build the Docker images, download the Redis and Postgres images, and start all the services.
    ```bash
    docker-compose up --build
    ```

The platform is now running!

---

## How to Use Project Nightingale V2

### 1. Explore the API Documentation
The easiest way to start is by using the interactive API documentation automatically generated by FastAPI.

**Open your browser and navigate to:** `http://localhost:8000/docs`

You will see all the available endpoints, and you can directly interact with them from the UI.

### 2. Run a Scan via `curl`
You can also use a command-line tool like `curl` to submit a scan job.

```bash
curl -X 'POST' \
  'http://localhost:8000/scans' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "example.com",
    "profile": "full",
    "rate_limit": 100,
    "owasp_top_10": true,
    "severity": [
        "critical",
        "high"
    ],
    "header": "Cookie: session=your_auth_cookie_here"
}'
```

You will get a response like this, which contains the ID of your scan task:
```json
{
  "message": "Scan submitted successfully.",
  "scan_id": "ab123cde-4567-890f-gh12-ijklmnopqrst"
}
```

### 3. Check Scan Status
Use the `scan_id` from the response above to check the status of your job.

```bash
curl -X 'GET' \
  'http://localhost:8000/scans/ab123cde-4567-890f-gh12-ijklmnopqrst' \
  -H 'accept: application/json'
```

The response will show the current state of the task (e.g., `PENDING`, `STARTED`, `SUCCESS`).

---

## Future Roadmap

This V2 architecture is a foundation. Future enhancements include:
- [ ] **Web Dashboard:** A React or Vue.js frontend to visualize scan results and manage projects.
- [ ] **Advanced Reporting:** Generate professional PDF and HTML reports from the data in PostgreSQL.
- [ ] **User Authentication:** Implement JWT-based authentication for a true multi-user PTaaS.
- [ ] **Expanded Toolchain:** Integrate more tools for secret scanning, visual reconnaissance, and deeper analysis.
- [ ] **Findings Correlation:** Add logic to correlate findings from different tools to identify more complex vulnerabilities.

## Contributing
Contributions are welcome! Please feel free to open an issue or submit a pull request.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.
