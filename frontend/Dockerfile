
FROM node:20.15.0-alpine AS builder

WORKDIR /app

# Build-time React env flags
ARG DISABLE_ESLINT_PLUGIN=true
ARG SKIP_PREFLIGHT_CHECK=true
ARG REACT_APP_API_URL=http://localhost:8000
ARG REACT_APP_WS_URL=ws://localhost:8000
ARG REACT_APP_API_TIMEOUT=30000
# Note: Supabase keys should be set at runtime or via CI/CD, not in Dockerfile
# Only set these if you understand they will be PUBLIC in the built JavaScript
ARG REACT_APP_SUPABASE_URL
ARG REACT_APP_SUPABASE_ANON_KEY

# Security: Validate that we're not accidentally including service keys
RUN if echo "$REACT_APP_SUPABASE_ANON_KEY" | grep -i "service_role" > /dev/null 2>&1; then \
      echo "ERROR: Service role key detected! Never use service keys in frontend."; \
      exit 1; \
    fi

ENV DISABLE_ESLINT_PLUGIN=${DISABLE_ESLINT_PLUGIN} \
    SKIP_PREFLIGHT_CHECK=${SKIP_PREFLIGHT_CHECK} \
    REACT_APP_API_URL=${REACT_APP_API_URL} \
    REACT_APP_WS_URL=${REACT_APP_WS_URL} \
    REACT_APP_API_TIMEOUT=${REACT_APP_API_TIMEOUT} \
    REACT_APP_SUPABASE_URL=${REACT_APP_SUPABASE_URL} \
    REACT_APP_SUPABASE_ANON_KEY=${REACT_APP_SUPABASE_ANON_KEY}

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM nginx:alpine

COPY --from=builder /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
