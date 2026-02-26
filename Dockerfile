# Stage 1: Get the official Nuclei binary
FROM projectdiscovery/nuclei:latest AS nuclei-builder

# Stage 2: Create the Tarsius Node.js environment
FROM node:20-alpine

# Install necessary Alpine packages for networking, execution, and external tool dependencies
RUN apk add --no-cache \
    bash \
    curl \
    ca-certificates \
    ruby \
    ruby-dev \
    build-base \
    libffi-dev \
    zlib-dev \
    libxml2-dev \
    libxslt-dev \
    perl \
    perl-doc \
    perl-libwww \
    git

# Install WPScan (Ruby)
RUN gem install wpscan

# Install JoomScan (Perl)
WORKDIR /opt
RUN git clone https://github.com/OWASP/joomscan.git && \
    chmod +x /opt/joomscan/joomscan.pl

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
