FROM node:26.3.0-bookworm-slim@sha256:3fe807a03a4436e7bc76b7e84e6861899cd75c9028ae99bc00581940141ae150 AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --ignore-scripts
COPY src ./src
COPY tests/*.test.ts ./tests/
RUN npm run build

FROM node:26.3.0-bookworm-slim@sha256:3fe807a03a4436e7bc76b7e84e6861899cd75c9028ae99bc00581940141ae150 AS dashboard
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY web ./web
COPY evidence/results.json ./evidence/results.json
USER 10001:10001
ENV BOUNTYPROOF_CONTAINER=1
CMD ["node", "dist/src/server.js"]

FROM python:3.14.6-slim@sha256:7bec7ddcddeff7975d6ba9b4be7dd6f6b2f55e7491539145e2978f7f97ce9144 AS lab
WORKDIR /app
COPY lab ./lab
COPY tools/container_lab.py ./tools/container_lab.py
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["python", "-m", "tools.container_lab"]
