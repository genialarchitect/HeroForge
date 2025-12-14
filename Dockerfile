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

# Create data directory for database
RUN mkdir -p /data

# Expose port 8080
EXPOSE 8080

# Run the application
CMD ["/app/heroforge", "serve", "--bind", "0.0.0.0:8080", "--database", "sqlite:/data/heroforge.db"]
