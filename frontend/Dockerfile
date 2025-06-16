FROM node:16-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Clear npm cache and install dependencies with legacy peer deps
RUN npm cache clean --force && npm install --legacy-peer-deps

# Copy the rest of the application
COPY . .

# Install additional dependencies that might be missing
RUN npm install --legacy-peer-deps \
    @mui/icons-material@5.15.3 \
    @mui/material@5.15.3 \
    framer-motion@10.16.4 \
    lucide-react@0.294.0 \
    recharts@2.10.3 \
    @radix-ui/react-accordion@1.1.2 \
    tailwind-merge@2.1.0 \
    tailwindcss-animate@1.0.7 \
    @tailwindcss/typography@0.5.10

EXPOSE 3000

# Command to run the application
CMD ["npm", "start"] 