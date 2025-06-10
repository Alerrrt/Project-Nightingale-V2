# scanner-frontend/Dockerfile
FROM node:18-alpine

WORKDIR /app

# Install dependencies
COPY package.json package-lock.json ./
RUN npm ci

# Copy source
COPY . .

# Expose Vite dev port
EXPOSE 5173

# Start dev server
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]