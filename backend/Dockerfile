# Use an official Python runtime as a parent image
FROM python:3.9-slim

WORKDIR /app

# --- LAYER 1: Install OS & Go Dependencies (Least frequent changes go first) ---
# This layer will almost never be rebuilt.
ENV GO_VERSION 1.22.4
RUN apt-get update && apt-get install -y --no-install-recommends wget ca-certificates nmap \
    && wget https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz -O go.tar.gz \
    && tar -C /usr/local -xzf go.tar.gz \
    && rm go.tar.gz \
    && apt-get purge -y --auto-remove wget \
    && rm -rf /var/lib/apt/lists/*
ENV GOPATH /go
ENV PATH /usr/local/go/bin:$GOPATH/bin:$PATH


# --- LAYER 2: Install Go Tools (Infrequent changes) ---
# This layer will only rebuild if you decide to change which tools are installed.
# The `RUN` commands are combined to create a single, more efficient layer.
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest


# --- LAYER 3: Install Python Dependencies (Occasional changes) ---
# Copy ONLY requirements.txt first. This layer will only rebuild if you change your Python dependencies.
COPY ./requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt


# --- LAYER 4: Copy Application Code (Frequent changes go last) ---
# This is the last step. Now, when you change your Python code, only this fast 'COPY' command will run.
# All the slow installations above will be loaded from the cache.
COPY . /app