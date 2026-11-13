# Pool deposits with the person's own NEAR wallet

A pool deposit is sent and signed by the person's own NEAR wallet, never by ONA (docs/desktop/pool-commands.md): the
`deposit` transaction from the depositing account, then an off-chain signature (NEP-413) of the message the pool agent
asks for before it issues the cash. Both desktop apps (macOS and Tauri) do it the same way.

## How it works

1. In the Pool window, a deposit is prepared (`pool_prepare`, account and amount) and its summary shown. **Ouvrir mon
   portefeuille** starts a small server on `127.0.0.1` (port chosen by the system) and opens
   `http://127.0.0.1:<port>/wallet/<16 random bytes in hex>/` in the default browser. One deposit at a time; the address
   works only for that deposit and only until the preparation expires (5 minutes, `summary.expires_at`).
2. The page (`desktop/wallet-page`) reads what to do from the app (`state`: account, amount, contract, network; never
   the prepared id) and opens NEAR Wallet Selector: MyNearWallet, Meteor, HERE, Intear. Only the depositing account
   may be used.
3. The wallet sends the `deposit` call (`summary.wallet_call`, 30 Tgas). The page tells the app (`deposited`), which
   runs the first `pool_execute`: the cash notes are made and saved, and the message to sign comes back.
4. The page asks the same wallet to sign that message (`signMessage`: message, recipient, nonce) and gives the
   signature to the app (`signed`), which runs the second `pool_execute`. Done, or queued by the agent: the cash then
   comes with **Récupérer** (`pool_recover`).

A wallet that sends the browser away and back (MyNearWallet) returns to the same page; the app keeps where the deposit
is. A step sent twice (a page reloaded) runs nothing again.

The server answers only `Host: 127.0.0.1:<port>`, and a POST only with `Origin: http://127.0.0.1:<port>`: another site
open in the browser cannot drive the deposit, even if it guessed the address. Files are sent with `nosniff`, `no-store`
and `no-referrer`.

## The page

`desktop/wallet-page`: `src/main.js` and `src/index.html`, bundled by esbuild into `dist/` (`wallet.js`, about 2.3 MB,
`wallet.css`, `index.html`), which the apps embed: the Tauri app with `include_bytes!`, the macOS app as the `dist`
resource folder. Nothing is loaded from a CDN. To rebuild after a change:

```
cd desktop/wallet-page && npm ci && npm run build
```

`npm ci` installs the exact versions of `package-lock.json`; npm 12 runs no install script by default. Two Node
built-ins some wallet libraries import are replaced by what they use of them (`src/shims`: `randomBytes` from the
browser's `crypto.getRandomValues`, `util.format`), and the bundle gets a minimal `process` object.

## Tested

- The server's checks and the two `pool_execute` steps: Rust tests (`wallet.rs`) and Swift tests (`WalletPageTests`,
  against a fake pool), including the refused `Host` and `Origin`.
- The page in a browser against a stand-in for the app: it reads the state, shows the deposit, and NEAR Wallet
  Selector lists the four wallets.
- **Not tested:** a deposit with a real wallet. That needs the pool on testnet and a funded testnet account; nothing
  has been sent from a real wallet, and the NEP-413 layout of `ona-agent` has not been checked against a real wallet's
  signature.
