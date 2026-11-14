// The page a desktop app opens in the browser for a pool deposit (docs/desktop/wallet.md).
//
// The app serves it on 127.0.0.1 under a random path that works for one deposit. The page asks the app what to do
// (`state`), then, with the person's own NEAR wallet through NEAR Wallet Selector:
//   1. sends the deposit transaction the app prepared (`wallet_call`), from the account named in the deposit;
//   2. reports it to the app, which makes the cash notes and returns the message the pool agent wants signed;
//   3. signs that message (NEP-413 `signMessage`) and gives the signature to the app, which asks for the cash.
// The app keeps the state: a wallet that sends the browser away and back (MyNearWallet) finds the page where it was.
// Nothing here sees the app's pool wallet or its keys; the wallet never sees anything but these two requests.
import { Buffer } from "buffer";
import { setupWalletSelector } from "@near-wallet-selector/core";
import { setupModal } from "@near-wallet-selector/modal-ui";
import { setupMyNearWallet } from "@near-wallet-selector/my-near-wallet";
import { setupMeteorWallet } from "@near-wallet-selector/meteor-wallet";
import { setupHereWallet } from "@near-wallet-selector/here-wallet";
import { setupIntearWallet } from "@near-wallet-selector/intear-wallet";

globalThis.Buffer = Buffer;

/** Gas for the deposit call: the local-node run measured 2.4 Tgas (SPEC), with a wide margin. */
const DEPOSIT_GAS = "30000000000000";

const $ = (id) => document.getElementById(id);
const base = location.pathname.replace(/\/$/, "");

async function app(step, body = {}) {
  const response = await fetch(`${base}/${step}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const reply = await response.json();
  if (!response.ok || reply.ok === false) throw new Error(reply.error || `error ${response.status}`);
  return reply;
}

function show(text, kind = "") {
  $("status").textContent = text;
  $("status").className = kind;
}

function near(yocto) {
  const digits = String(yocto).padStart(25, "0");
  const whole = digits.slice(0, -24).replace(/^0+(?=\d)/, "");
  const fraction = digits.slice(-24).replace(/0+$/, "");
  return `${fraction ? `${whole}.${fraction}` : whole} NEAR`;
}

/** What a wallet that navigated away put in the address when it sent the browser back. */
function returned() {
  const query = new URLSearchParams(location.search);
  const hash = new URLSearchParams(location.hash.slice(1));
  const clean = () => history.replaceState(null, "", location.pathname);
  if (query.get("transactionHashes")) {
    clean();
    return { tx: query.get("transactionHashes").split(",").pop() };
  }
  if (hash.get("signature")) {
    clean();
    return { signed: { accountId: hash.get("accountId"), publicKey: hash.get("publicKey"), signature: hash.get("signature") } };
  }
  if (query.get("errorCode") || hash.get("error")) {
    clean();
    return { error: query.get("errorMessage") || query.get("errorCode") || hash.get("error") };
  }
  return {};
}

/** "Connect wallet" in the app: no deposit, the page only tells the app which account the wallet uses. */
async function connect(state) {
  document.title = "ONA — connect your wallet";
  $("title").textContent = "Connect your NEAR wallet to ONA";
  $("details").hidden = true;
  $("help").textContent = "ONA only learns your account name. Every deposit is still sent and signed by your wallet, which asks you each time. ONA never sees your wallet's keys.";
  const selector = await setupWalletSelector({
    network: state.network === "mainnet" ? "mainnet" : "testnet",
    modules: [setupMyNearWallet(), setupMeteorWallet(), setupHereWallet(), setupIntearWallet()],
  });
  const modal = setupModal(selector, { description: "Choose your wallet (Meteor, for example)." });
  const signedInAs = () => selector.store.getState().accounts.find((a) => a.active)?.accountId;
  const report = async (account) => {
    const reply = await app("connected", { account });
    show(`Connected as ${reply.account}. You can close this page and go back to ONA.`, "ok");
    $("go").disabled = true;
  };
  const run = (work) => work().catch((e) => show(`Interrupted: ${e.message}`, "error"));
  $("go").textContent = "Connect my wallet";
  $("go").onclick = () => modal.show();
  selector.on("signedIn", () => run(async () => {
    const account = signedInAs();
    if (account) await report(account);
  }));
  // A wallet already connected in this browser (NEAR Wallet Selector remembers it for this address).
  const already = signedInAs();
  if (already) return run(() => report(already));
  $("go").disabled = false;
  show("Choose your wallet.");
}

async function main() {
  let state = await app("state");
  if (state.step === "connect") return connect(state);
  $("account").textContent = state.account;
  $("amount").textContent = near(state.wallet_call.attached);
  $("receiver").textContent = state.wallet_call.receiver;
  $("network").textContent = state.network;
  if (state.step === "done") return show("Deposit complete. You can close this page.", "ok");

  const back = returned();
  if (back.error) show(`The wallet refused: ${back.error}`, "error");

  const selector = await setupWalletSelector({
    network: state.network === "mainnet" ? "mainnet" : "testnet",
    modules: [setupMyNearWallet(), setupMeteorWallet(), setupHereWallet(), setupIntearWallet()],
  });
  const modal = setupModal(selector, { description: "Choose the wallet of the depositing account." });

  // Only the account named in the deposit: the contract issues cash to the account that deposited.
  const signedInAs = () => selector.store.getState().accounts.find((a) => a.active)?.accountId;
  const wallet = async () => {
    const account = signedInAs();
    if (account !== state.account) {
      throw new Error(account ? `the wallet is connected to ${account}, not to ${state.account}` : "no wallet connected");
    }
    return selector.wallet();
  };

  async function deposit() {
    show("Sending the deposit from your wallet…");
    const call = state.wallet_call;
    const outcome = await (await wallet()).signAndSendTransaction({
      signerId: state.account,
      receiverId: call.receiver,
      // Wallet Selector 10 takes near-api-js actions (`{ functionCall: … }`, args as JSON bytes, gas and deposit as
      // integers); the older `{ type: "FunctionCall", params }` form is refused with "Unsupported NAJ action".
      actions: [{
        functionCall: {
          methodName: call.method,
          args: Buffer.from(JSON.stringify(call.args)),
          gas: BigInt(DEPOSIT_GAS),
          deposit: BigInt(call.attached),
        },
      }],
    });
    // A wallet that navigates away comes back with the hash in the address instead (see `returned`).
    if (outcome) await deposited(outcome.transaction?.hash || outcome.transaction_outcome?.id || "");
  }

  async function deposited(tx) {
    show("Deposit sent. The computer is preparing your notes…");
    state = await app("deposited", { tx });
    await sign();
  }

  async function sign() {
    show("Sign the pool agent's message in your wallet…");
    const m = state.sign_message;
    const signed = await (await wallet()).signMessage({
      message: m.message,
      recipient: m.recipient,
      nonce: Buffer.from(m.nonce, "base64"),
      callbackUrl: location.href.split(/[?#]/)[0],
    });
    if (signed) await finish(signed);
  }

  async function finish(signed) {
    if (signed.accountId && signed.accountId !== state.account) throw new Error(`message signed by ${signed.accountId}`);
    show("Signature received. The pool agent is issuing your notes…");
    state = await app("signed", { public_key: signed.publicKey, signature: signed.signature });
    show(state.step === "done" ? "Deposit complete. You can close this page." : "Sent to the pool agent: the result will show up in the app (Recover).", "ok");
  }

  const run = (work) => work().catch((e) => show(`Interrupted: ${e.message}`, "error"));
  $("go").onclick = () => run(async () => {
    if (signedInAs() !== state.account) {
      modal.show();
      return;
    }
    if (state.step === "sign") return sign();
    return deposit();
  });
  selector.on("signedIn", () => run(async () => (state.step === "sign" ? sign() : deposit())));

  if (back.tx && state.step === "deposit") return run(() => deposited(back.tx));
  if (back.signed && state.step === "sign") return run(() => finish(back.signed));
  $("go").disabled = false;
  if (state.step === "sign") return show("The pool agent's message still needs your signature.");
  if (signedInAs() === state.account) {
    $("go").textContent = "Send the deposit with my wallet";
    return show(`Your wallet is connected as ${state.account}. Click to send the deposit: your wallet asks you to confirm it.`);
  }
  show("Connect the wallet of the depositing account.");
}

main().catch((e) => show(`Error: ${e.message}`, "error"));
