FROM debian:trixie-slim

# Install required dependencies including VPN tools
RUN apt-get update && apt-get install -y \
    ca-certificates \
    openvpn \
    wireguard-tools \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy the compiled binary and frontend
COPY target/release/heroforge /app/heroforge
COPY frontend/dist /app/frontend/dist

# Create non-root user and group
RUN groupadd -r -g 1000 heroforge && \
    useradd -r -u 1000 -g heroforge heroforge

# Create data directory for database and VPN configs, set ownership
RUN mkdir -p /data /app/vpn_configs /etc/wireguard && \
    chown -R heroforge:heroforge /app /data /app/vpn_configs

# Note: VPN operations require CAP_NET_ADMIN and access to /dev/net/tun
# The container will run the web server as heroforge user, but VPN operations
# are executed via system commands that require elevated privileges.
# The container should be run with --cap-add=NET_ADMIN --device=/dev/net/tun

# Switch to non-root user for the main application
USER heroforge

# Expose port 8080
EXPOSE 8080

# Environment variables
ENV VPN_CONFIGS_DIR=/app/vpn_configs

# Run the application
CMD ["/app/heroforge", "serve", "--bind", "0.0.0.0:8080", "--database", "sqlite:/data/heroforge.db"]
