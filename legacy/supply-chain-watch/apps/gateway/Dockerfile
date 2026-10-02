# syntax=docker/dockerfile:1
FROM node:22-alpine AS base
RUN corepack enable
WORKDIR /repo

FROM base AS build
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml tsconfig.base.json ./
COPY packages/shared-types/package.json packages/shared-types/
COPY apps/gateway/package.json apps/gateway/
RUN pnpm install --frozen-lockfile --filter @scw/gateway... 
COPY packages/shared-types packages/shared-types
COPY apps/gateway apps/gateway
RUN pnpm --filter @scw/shared-types build && pnpm --filter @scw/gateway build

FROM base AS runtime
ENV NODE_ENV=production
COPY --from=build /repo /repo
WORKDIR /repo/apps/gateway
EXPOSE 4000
CMD ["node", "dist/index.js"]
