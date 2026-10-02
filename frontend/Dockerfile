# APEX-X frontend (Next.js) - build context: frontend/
FROM node:20-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --legacy-peer-deps

FROM node:20-slim AS build
WORKDIR /app
# The browser calls the API on the frontend's own origin (/api/v1); Next.js
# proxies it to the backend container. Rewrites are resolved at build time.
ARG NEXT_PUBLIC_API_URL=/api/v1
ARG BACKEND_INTERNAL_URL=http://backend:8080
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL} BACKEND_INTERNAL_URL=${BACKEND_INTERNAL_URL} NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build && npm prune --omit=dev --legacy-peer-deps

FROM node:20-slim AS run
WORKDIR /app
ARG BACKEND_INTERNAL_URL=http://backend:8080
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 BACKEND_INTERNAL_URL=${BACKEND_INTERNAL_URL}
COPY --from=build --chown=node:node /app/package.json ./
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/.next ./.next
COPY --from=build --chown=node:node /app/public ./public
COPY --from=build --chown=node:node /app/next.config.ts ./
USER node
EXPOSE 3000
CMD ["npx", "next", "start", "-p", "3000", "-H", "0.0.0.0"]
