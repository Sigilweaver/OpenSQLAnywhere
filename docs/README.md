# OpenSQLAnywhere docs site

[Docusaurus](https://docusaurus.io/) site for the OpenSQLAnywhere
project. Deploys to <https://sigilweaver.app/opensqlanywhere/docs/>
via Cloudflare Workers.

## Develop

```sh
bun install
bun run dev          # http://localhost:25814/opensqlanywhere/docs/
```

## Build and deploy

CI auto-deploys on push to `main`. For a local deploy:

```sh
bun run deploy       # builds to ./build/opensqlanywhere/docs and runs wrangler deploy
```
