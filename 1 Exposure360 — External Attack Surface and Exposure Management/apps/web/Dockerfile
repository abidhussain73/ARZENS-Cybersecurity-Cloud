FROM node:22-alpine
WORKDIR /app
COPY apps/web/package.json apps/web/pnpm-lock.yaml ./
RUN npm install --global pnpm@9.15.4 && pnpm install --frozen-lockfile
COPY apps/web ./
EXPOSE 5173
CMD ["pnpm", "dev"]
