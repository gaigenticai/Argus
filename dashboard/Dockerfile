FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

ENV NEXT_PUBLIC_API_URL=https://argus-api-production.up.railway.app/api/v1

RUN npm run build

ENV PORT=3000
EXPOSE 3000

CMD ["npm", "start"]
