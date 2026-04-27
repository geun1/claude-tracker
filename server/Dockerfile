FROM node:24-alpine
RUN apk add --no-cache python3 make g++ sqlite
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY server.js dashboard.html ./
COPY pricing.json* ./
ENV PORT=3737
ENV TRACKER_DB=/data/tracker.db
VOLUME ["/data"]
EXPOSE 3737
CMD ["node", "server.js"]
