# Frontend Dockerfile
FROM node:18-alpine AS builder

WORKDIR /app/frontend

# Build arguments for React environment variables (baked at build time)
# ===== Build Control =====
ARG DISABLE_ESLINT_PLUGIN=true
ARG SKIP_PREFLIGHT_CHECK=true

# ===== API Configuration =====
ARG REACT_APP_API_URL=http://localhost:8000
ARG REACT_APP_WS_URL=ws://localhost:8000
ARG REACT_APP_API_TIMEOUT=30000

# ===== Supabase Configuration =====
ARG REACT_APP_SUPABASE_URL
ARG REACT_APP_SUPABASE_ANON_KEY

# Set environment variables for the build
# ===== Build Control =====
ENV DISABLE_ESLINT_PLUGIN=$DISABLE_ESLINT_PLUGIN
ENV SKIP_PREFLIGHT_CHECK=$SKIP_PREFLIGHT_CHECK

# ===== API Configuration =====
ENV REACT_APP_API_URL=$REACT_APP_API_URL
ENV REACT_APP_WS_URL=$REACT_APP_WS_URL
ENV REACT_APP_API_TIMEOUT=$REACT_APP_API_TIMEOUT

# ===== Supabase Configuration =====
ENV REACT_APP_SUPABASE_URL=$REACT_APP_SUPABASE_URL
ENV REACT_APP_SUPABASE_ANON_KEY=$REACT_APP_SUPABASE_ANON_KEY

# Copy package files
COPY package.json package-lock.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY . .

# Build application with env vars baked in
RUN npm run build

# Production stage
FROM node:18-alpine

WORKDIR /app/frontend

# Install serve to run production build
RUN npm install -g serve

# Copy built app from builder
COPY --from=builder /app/frontend/build ./build

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:3000 || exit 1

# Run application
CMD ["serve", "-s", "build", "-l", "3000"]
