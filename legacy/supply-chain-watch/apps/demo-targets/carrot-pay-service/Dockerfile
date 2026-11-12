# syntax=docker/dockerfile:1
# 빌드 컨텍스트는 저장소 루트(compose에서 지정). 오염 데모 패키지를 vendor/로 함께 담는다.
FROM node:22-alpine
RUN apk add --no-cache curl
WORKDIR /app
ENV NODE_ENV=production
COPY packages/demo-packages/pay-analytics-demo ./vendor/pay-analytics-demo
COPY apps/demo-targets/carrot-pay-service/package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY apps/demo-targets/carrot-pay-service/src ./src
USER node
EXPOSE 3000
HEALTHCHECK --interval=5s --timeout=3s --retries=10 CMD wget -qO- http://127.0.0.1:3000/health >/dev/null || exit 1
CMD ["node", "src/server.js"]
