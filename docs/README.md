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

Cloudflare deploys automatically via the GitHub App on push to `main`.
To verify the build locally:

```sh
bun run build:cloudflare
```
