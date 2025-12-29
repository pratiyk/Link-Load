
# Frontend Dockerfile using Nginx
FROM node:18-alpine AS builder

WORKDIR /app/frontend

# Build arguments for React environment variables (baked at build time)
ARG DISABLE_ESLINT_PLUGIN=true
ARG SKIP_PREFLIGHT_CHECK=true
ARG REACT_APP_API_URL=http://localhost:8000
ARG REACT_APP_WS_URL=ws://localhost:8000
ARG REACT_APP_API_TIMEOUT=30000
ARG REACT_APP_SUPABASE_URL
ARG REACT_APP_SUPABASE_ANON_KEY

ENV DISABLE_ESLINT_PLUGIN=$DISABLE_ESLINT_PLUGIN
ENV SKIP_PREFLIGHT_CHECK=$SKIP_PREFLIGHT_CHECK
ENV REACT_APP_API_URL=$REACT_APP_API_URL
ENV REACT_APP_WS_URL=$REACT_APP_WS_URL
ENV REACT_APP_API_TIMEOUT=$REACT_APP_API_TIMEOUT
ENV REACT_APP_SUPABASE_URL=$REACT_APP_SUPABASE_URL
ENV REACT_APP_SUPABASE_ANON_KEY=$REACT_APP_SUPABASE_ANON_KEY

# Copy package files and install dependencies
COPY package.json package-lock.json ./
RUN npm ci

# Copy source code and build
COPY . .
COPY .env .env
RUN npm run build

# Production stage: use Nginx
FROM nginx:alpine
WORKDIR /usr/share/nginx/html

# Remove default Nginx static assets
RUN rm -rf ./*

# Copy build output and nginx.conf
COPY --from=builder /app/frontend/build .
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
