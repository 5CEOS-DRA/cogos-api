FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM node:20-alpine
WORKDIR /app
RUN apk add --no-cache wget && \
    addgroup -S app && adduser -S app -G app
COPY --from=deps /app/node_modules ./node_modules
COPY --chown=app:app src ./src
COPY --chown=app:app package.json ./
RUN mkdir -p /app/data && chown -R app:app /app/data
ENV NODE_ENV=production \
    PORT=4444
USER app
EXPOSE 4444
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:4444/health || exit 1
CMD ["node", "src/index.js"]
