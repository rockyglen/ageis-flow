# Build Stage
# CHANGED: Updated from node:18-alpine to node:20-alpine
FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json ./
ENV NODE_OPTIONS="--max-old-space-size=1024"
RUN npm install
COPY . .
RUN npm run build

# Run Stage
# CHANGED: Updated from node:18-alpine to node:20-alpine
FROM node:20-alpine
WORKDIR /app
COPY --from=builder /app/package.json .
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/node_modules ./node_modules

EXPOSE 3000
CMD ["npm", "start"]