# syntax=docker/dockerfile:1
#
# ThirdSentry container images (two targets, one build):
#
#   slim     (thirdsentry:slim)  Node.js only, no browsers. Used by every container that
#                                never runs a browser: egress-proxy, analyzer, alerter, tools.
#   browser  (thirdsentry:local) Microsoft's Playwright image (Node.js + Chromium, Firefox,
#                                WebKit). Used by the scanner only. This is the LAST stage,
#                                so a plain `docker build .` produces it.
#
#   docker build --target slim    -t thirdsentry:slim  .
#   docker build --target browser -t thirdsentry:local .
#
# Keep PLAYWRIGHT_IMAGE in sync with the "playwright" version in package.json, and
# NODE_IMAGE on the same Node.js major as the Playwright image
# (docker run --rm --entrypoint node <playwright image> -v).
ARG PLAYWRIGHT_IMAGE=mcr.microsoft.com/playwright:v1.65.1-noble
ARG NODE_IMAGE=node:26-bookworm-slim

FROM ${NODE_IMAGE} AS build
WORKDIR /src
COPY package.json package-lock.json ./
# --ignore-scripts: no install scripts from dependencies run during the build.
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npx tsc -p tsconfig.build.json \
 && npm prune --omit=dev --ignore-scripts --no-audit --no-fund

FROM ${NODE_IMAGE} AS slim
LABEL org.opencontainers.image.title="ThirdSentry (slim)" \
      org.opencontainers.image.description="Third-party JavaScript security monitoring: components without a browser" \
      org.opencontainers.image.licenses="Apache-2.0"
ENV NODE_ENV=production \
    NO_UPDATE_NOTIFIER=1
WORKDIR /opt/thirdsentry
COPY --from=build /src/package.json ./package.json
COPY --from=build /src/node_modules ./node_modules
COPY --from=build /src/dist ./dist
COPY LICENSE README.md ./
# Same account name and uid as the Playwright image ("pwuser", 1001) so volumes
# are interchangeable between both images.
RUN groupadd --gid 1001 pwuser \
 && useradd --uid 1001 --gid 1001 --create-home --shell /usr/sbin/nologin pwuser \
 && mkdir -p /work/.thirdsentry/reports /work/.thirdsentry/state /work/.thirdsentry/cache /work/.thirdsentry/baselines /evidence /proxy-events \
 && chown -R pwuser:pwuser /work /evidence /proxy-events
USER pwuser
WORKDIR /work
ENTRYPOINT ["node", "/opt/thirdsentry/dist/cli/bin.js"]
CMD ["--help"]

FROM ${PLAYWRIGHT_IMAGE} AS browser
LABEL org.opencontainers.image.title="ThirdSentry" \
      org.opencontainers.image.description="Third-party JavaScript security monitoring" \
      org.opencontainers.image.licenses="Apache-2.0"
ENV NODE_ENV=production \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    NO_UPDATE_NOTIFIER=1
WORKDIR /opt/thirdsentry
COPY --from=build /src/package.json ./package.json
COPY --from=build /src/node_modules ./node_modules
COPY --from=build /src/dist ./dist
COPY LICENSE README.md ./
# Pre-create mount points owned by the unprivileged user so that named volumes
# inherit the right ownership. The image already contains the "pwuser" account.
RUN mkdir -p /work/.thirdsentry/reports /work/.thirdsentry/state /work/.thirdsentry/cache /work/.thirdsentry/baselines /evidence \
 && chown -R pwuser:pwuser /work /evidence
USER pwuser
WORKDIR /work
ENTRYPOINT ["node", "/opt/thirdsentry/dist/cli/bin.js"]
CMD ["--help"]
