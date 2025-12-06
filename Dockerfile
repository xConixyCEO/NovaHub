FROM node:22-slim

# 1. Install Lua 5.1 and its dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends lua5.1 && \
    rm -rf /var/lib/apt/lists/*

# 2. Set the working directory
WORKDIR /usr/src/app

# 3. Copy package.json and install Node dependencies
COPY package*.json ./
RUN npm install

# 4. Copy the rest of the application code
COPY . .

# 5. Expose the port (Render will use this)
EXPOSE 3000

# 6. Define the command to start the app
CMD [ "npm", "start" ]
