FROM debian:trixie-slim

# Install required dependencies including VPN tools, PDF generation, and packet capture
RUN apt-get update && apt-get install -y \
    ca-certificates \
    openvpn \
    wireguard-tools \
    iproute2 \
    iptables \
    curl \
    unzip \
    whois \
    chromium \
    fontconfig \
    fonts-liberation \
    fonts-dejavu-core \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei (vulnerability scanner)
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /tmp \
    && mv /tmp/nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei.zip /tmp/README.md /tmp/LICENSE.md

# Create app directory
WORKDIR /app

# Copy the compiled binary and frontend
COPY target/release/heroforge /app/heroforge
COPY frontend/dist /app/frontend/dist

# Create non-root user and group with home directory
RUN groupadd -r -g 1000 heroforge && \
    useradd -r -u 1000 -g heroforge -m -d /home/heroforge heroforge

# Create data directory for database, VPN configs, and nuclei config, set ownership
RUN mkdir -p /data /app/vpn_configs /etc/wireguard /home/heroforge/.config/nuclei /home/heroforge/.cache/nuclei && \
    chown -R heroforge:heroforge /app /data /app/vpn_configs /home/heroforge

# Note: VPN operations require CAP_NET_ADMIN and access to /dev/net/tun
# The container will run the web server as heroforge user, but VPN operations
# are executed via system commands that require elevated privileges.
# The container should be run with --cap-add=NET_ADMIN --device=/dev/net/tun

# Switch to non-root user for the main application
USER heroforge

# Set HOME for the heroforge user
ENV HOME=/home/heroforge

# Download Nuclei templates (as heroforge user so templates are properly owned)
RUN nuclei -ut || true

# Expose port 8080
EXPOSE 8080

# Environment variables
ENV VPN_CONFIGS_DIR=/app/vpn_configs

# Run the application
CMD ["/app/heroforge", "serve", "--bind", "0.0.0.0:8080", "--database", "sqlite:/data/heroforge.db"]
