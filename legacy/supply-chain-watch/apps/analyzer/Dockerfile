# syntax=docker/dockerfile:1
FROM node:22-alpine AS base
RUN corepack enable
WORKDIR /repo

FROM base AS build
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml tsconfig.base.json ./
COPY packages/shared-types/package.json packages/shared-types/
COPY apps/analyzer/package.json apps/analyzer/
RUN pnpm install --frozen-lockfile --filter @scw/analyzer... 
COPY packages/shared-types packages/shared-types
COPY apps/analyzer apps/analyzer
RUN pnpm --filter @scw/shared-types build && pnpm --filter @scw/analyzer build

FROM base AS runtime
ENV NODE_ENV=production
COPY --from=build /repo /repo
WORKDIR /repo/apps/analyzer
EXPOSE 4100
CMD ["node", "dist/index.js"]
