FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

ENV NEXT_PUBLIC_API_URL=https://api.argusai.xyz/api/v1

RUN npm run build

ENV PORT=3000
EXPOSE 3000

CMD ["npm", "start"]

