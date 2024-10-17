# Use the official Golang image
FROM golang:1.23

# Set environment variables to avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    make \
    gcc \
    g++ \
    ca-certificates \
    build-essential \
    wget \
    apt-transport-https \
    gnupg2 \
    docker.io \
    python3 \
    python3-pip \
    sudo && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set Go environment for building Copacetic
ENV GO111MODULE=on

# Install Trivy
RUN wget https://github.com/aquasecurity/trivy/releases/download/v0.34.0/trivy_0.34.0_Linux-64bit.deb && \
    dpkg -i trivy_0.34.0_Linux-64bit.deb

# Verify Go installation
RUN go version

# Clone and install Copacetic
RUN git clone https://github.com/project-copacetic/copacetic && \
    cd /go/copacetic && \
    make build

# Verify files after Copacetic build
RUN ls /go/copacetic/dist/linux_amd64/release/

# Move the Copacetic binary to the correct location
RUN mv /go/copacetic/dist/linux_amd64/release/copa /usr/local/bin



# Install Python dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-venv
# Set the working directory before creating the virtual environment
WORKDIR /app
RUN python3 -m venv venv
WORKDIR /app
# Create the virtual environment in /app
RUN python3 -m venv venv
# Copy application files and requirements.txt
COPY . /app
COPY requirements.txt /app/requirements.txt
# Install dependencies using the virtual environment's pip
RUN venv/bin/pip install --upgrade pip && \
    venv/bin/pip install --no-cache-dir -r requirements.txt


# Allow the container to run Docker commands
RUN usermod -aG docker root

# Expose the port Flask will run on
EXPOSE 5000
# Set the entry point to start the Flask app with Gunicorn
# Start the Flask app using Gunicorn within the virtual environment
CMD ["sh", "-c", "./venv/bin/gunicorn -w 1 -b 0.0.0.0:5000 app:app  --worker-class gevent"]

