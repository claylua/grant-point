# syntax=docker/dockerfile:1

FROM node:20-alpine AS base
WORKDIR /app
ENV NODE_ENV=production

# Install dependencies using the lockfile for reproducible builds
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Copy the application source
COPY src ./src

EXPOSE 4000 4443

CMD ["npm", "start"]
