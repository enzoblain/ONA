# ONA — shared instructions (all components)

Read `README.md` first: it is the public description of the planned design. Nothing is built yet.

## Team rules (apply everywhere)

- **No key or secret** in code, config, docs or a conversation. The iOS side never needs the NEAR AI key.
- **Pinned versions.** Every dependency is pinned to an exact version. Each library is listed in the README section
  "Libraries and AI-generated code" when it is adopted. AI-generated code is declared there too.
- **No untested claim in public text** (README, docs meant for publication). A claim gets a test or is removed.
- **Git:** commit and push when the user asks; work goes on a branch, not directly on `main`.

## Ownership — one CLAUDE.md per component

Each component has its own `CLAUDE.md` in its folder, owned by the person working on it. Claude Code loads the one of the
folder you work in, on top of this file. Do not edit another person's component instructions.

| Folder | Component | Owner |
|---|---|---|
| `ios/` | iOS remote-control app (Swift) | Enzo |
| (to be created) | `ona-core`, desktop app, `ona-server`, `ona-signer`, contracts | Hugo |

Docs per component live in `docs/<component>/`. `docs/` holds internal team notes: review before making the repo public.
