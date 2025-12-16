FROM debian:trixie-slim

# Install required dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy the compiled binary and frontend
COPY target/release/heroforge /app/heroforge
COPY frontend/dist /app/frontend/dist

# Create non-root user and group
RUN groupadd -r -g 1000 heroforge && \
    useradd -r -u 1000 -g heroforge heroforge

# Create data directory for database and set ownership
RUN mkdir -p /data && \
    chown -R heroforge:heroforge /app /data

# Switch to non-root user
USER heroforge

# Expose port 8080
EXPOSE 8080

# Run the application
CMD ["/app/heroforge", "serve", "--bind", "0.0.0.0:8080", "--database", "sqlite:/data/heroforge.db"]
