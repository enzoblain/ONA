# Contributing

- Run `./verify.sh` before pushing. It must pass.
- A security property needs a test that fails when the property is broken. For contract changes, check this by breaking the code once.
- Anything faked must say so: a fake model, web or chain labels its replies `mode: mock`.
- A claim in the README or `SPEC.md` is either tested or marked as not verified.
- Never commit a key, a seed or a `.env` file. Each deployment needs its own mint keys: see `SPEC.md`.
- Contracts have no upgrade path, and the mint holds no real funds until it has been audited.
- New NEAR methods need an entry in the `SPEC.md` table, with what they must refuse.
- Any command, environment variable or visible behaviour you add goes in `docs/INSTALL.md` in the same commit.
