FROM mcr.microsoft.com/playwright:v1.43.1-jammy

WORKDIR /app

COPY package.json ./
RUN npm install --production

COPY server.js ./

USER pwuser

EXPOSE 3000

CMD ["node", "server.js"]
