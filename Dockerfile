# Stage 1: Get the official Nuclei binary
FROM projectdiscovery/nuclei:latest AS nuclei-builder

# Stage 2: Create the Tarsius Node.js environment
FROM node:20-alpine

# Install necessary Alpine packages for networking/execution
RUN apk add --no-cache bash curl ca-certificates

# Copy Nuclei binary from Stage 1 into the system path
COPY --from=nuclei-builder /usr/local/bin/nuclei /usr/local/bin/nuclei

# Set the working directory for Tarsius
WORKDIR /opt/tarsius

# Copy package files and install production dependencies
COPY package*.json ./
RUN npm install --omit=dev

# Copy the rest of the Tarsius source code
COPY . .

# Set the entrypoint so running the container runs the Tarsius CLI
ENTRYPOINT ["node", "bin/tarsius"]
