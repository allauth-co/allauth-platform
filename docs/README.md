# Documentation source

For AllAuth, start with the React SDK quickstart or the self-hosting guide. AllAuth integration guides in this tree cover features such as MFA, organizations, enterprise providers and application configuration. [React SDK quickstart](https://allauth.co/sdk/quickstart) · [Self-hosting](SELF_HOSTING.md) · [Integration guides](content/docs/integrations)

This Next.js site and its framework reference originate from the upstream Better Auth documentation. The source below is useful when working on the vendored packages. [Upstream documentation](https://better-auth.com/docs) · [Third-party notices](../THIRD_PARTY_NOTICES.md)

## Quick Start

```bash
# install
pnpm install

# develop
pnpm dev
```

Open **[localhost:3000](http://localhost:3000)** to preview.

## Stack

* **Framework**: Next.js 16 (App Router, Turbopack)
* **Styling**: Tailwind CSS 4
* **Animation**: Framer Motion
* **Docs**: Fumadocs
* **Icons**: Lucide React
* **Fonts**: Geist Sans & Geist Mono

## Structure

```
├─ app/
│  ├─ page.tsx              # Home — hero + sign-in demo
│  ├─ products/             # Products page
│  ├─ blog/                 # Blog posts
│  └─ docs/[[...slug]]/     # Documentation (MDX)
│
├─ components/
│  ├─ landing/              # Marketing components
│  ├─ docs/                 # Documentation components
│  ├─ ui/                   # Shared primitives
│  └─ icons/                # Brand icons & logo
│
├─ content/                 # MDX documentation files
│
├─ lib/
│  ├─ source.ts             # Fumadocs content source
│  └─ utils.ts              # Utilities
│
└─ public/
   └─ branding/             # Logo assets (SVG + PNG)
```

## Scripts

```bash
pnpm dev          # Start dev server (Turbopack)
pnpm build        # Production build
pnpm start        # Serve production build
pnpm lint:fix     # Lint & auto-fix with Biome
```
