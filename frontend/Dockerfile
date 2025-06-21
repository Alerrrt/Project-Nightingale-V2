# Use Debian-based Node image for best compatibility
FROM node:20

WORKDIR /app

# Copy only package files first for better Docker cache
COPY package.json package-lock.json* ./

# Install dependencies (this installs vite and all dev dependencies)
RUN npm install

# Copy the rest of your app
COPY . .

ENV PATH /app/node_modules/.bin:$PATH

EXPOSE 3002

# For development (Vite dev server)
CMD ["npm", "run", "dev", "--", "--host", "--port", "3002"]

# For production, use the following instead:
# RUN npm run build
# CMD ["npx", "serve", "dist"] 