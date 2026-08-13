# Samuel Oblika - Offensive Security Portfolio

Custom Astro portfolio for penetration-testing writeups and technical notes.

## Run locally

```bash
npm install
npm run dev
```

Then open the local URL printed by Astro, normally `http://localhost:4321`.

## Add a writeup

Create a new `.md` file inside:

```text
src/content/writeups/
```

Example frontmatter:

```yaml
---
title: "Lab title"
description: "Short summary"
date: 2026-08-12
platform: "Hack The Box"
difficulty: "Medium"
category: "Active Directory"
tags: ["bloodhound", "kerberos", "adcs"]
featured: true
readingTime: "12 min"
---
```

The writeup is automatically added to `/writeups` and gets its own URL.

## Main files

- `src/pages/index.astro` - homepage
- `src/pages/writeups/index.astro` - searchable writeup index
- `src/pages/writeups/[...slug].astro` - writeup template
- `src/styles/global.css` - visual design
- `src/content.config.ts` - Markdown collection schema
