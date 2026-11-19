# syntax=docker/dockerfile:1
#
# ThirdSentry container image.
#
# Based on Microsoft's Playwright image, which ships Node.js and browser builds
# (Chromium, Firefox, WebKit) matching the pinned Playwright version. Keep the
# tag in sync with the "playwright" version in package.json.
ARG PLAYWRIGHT_IMAGE=mcr.microsoft.com/playwright:v1.65.1-noble

FROM ${PLAYWRIGHT_IMAGE} AS build
WORKDIR /src
COPY package.json package-lock.json ./
# --ignore-scripts: no install scripts from dependencies run during the build.
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npx tsc -p tsconfig.build.json \
 && npm prune --omit=dev --ignore-scripts --no-audit --no-fund

FROM ${PLAYWRIGHT_IMAGE} AS runtime
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
