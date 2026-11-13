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
  if (!response.ok || reply.ok === false) throw new Error(reply.error || `erreur ${response.status}`);
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

async function main() {
  let state = await app("state");
  $("account").textContent = state.account;
  $("amount").textContent = near(state.wallet_call.attached);
  $("receiver").textContent = state.wallet_call.receiver;
  $("network").textContent = state.network;
  if (state.step === "done") return show("Dépôt terminé. Vous pouvez fermer cette page.", "ok");

  const back = returned();
  if (back.error) show(`Le portefeuille a refusé : ${back.error}`, "error");

  const selector = await setupWalletSelector({
    network: state.network === "mainnet" ? "mainnet" : "testnet",
    modules: [setupMyNearWallet(), setupMeteorWallet(), setupHereWallet(), setupIntearWallet()],
  });
  const modal = setupModal(selector, { description: "Choisissez le portefeuille du compte qui dépose." });

  // Only the account named in the deposit: the contract issues cash to the account that deposited.
  const signedInAs = () => selector.store.getState().accounts.find((a) => a.active)?.accountId;
  const wallet = async () => {
    const account = signedInAs();
    if (account !== state.account) {
      throw new Error(account ? `le portefeuille est connecté à ${account}, pas à ${state.account}` : "aucun portefeuille connecté");
    }
    return selector.wallet();
  };

  async function deposit() {
    show("Envoi du dépôt depuis votre portefeuille…");
    const call = state.wallet_call;
    const outcome = await (await wallet()).signAndSendTransaction({
      signerId: state.account,
      receiverId: call.receiver,
      actions: [{ type: "FunctionCall", params: { methodName: call.method, args: call.args, gas: DEPOSIT_GAS, deposit: call.attached } }],
    });
    // A wallet that navigates away comes back with the hash in the address instead (see `returned`).
    if (outcome) await deposited(outcome.transaction?.hash || outcome.transaction_outcome?.id || "");
  }

  async function deposited(tx) {
    show("Dépôt envoyé. L'ordinateur prépare vos billets…");
    state = await app("deposited", { tx });
    await sign();
  }

  async function sign() {
    show("Signez le message de l'agent du pool dans votre portefeuille…");
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
    if (signed.accountId && signed.accountId !== state.account) throw new Error(`message signé par ${signed.accountId}`);
    show("Signature reçue. L'agent du pool émet vos billets…");
    state = await app("signed", { public_key: signed.publicKey, signature: signed.signature });
    show(state.step === "done" ? "Dépôt terminé. Vous pouvez fermer cette page." : "Envoyé à l'agent du pool : le résultat arrivera dans l'app (Récupérer).", "ok");
  }

  const run = (work) => work().catch((e) => show(`Interrompu : ${e.message}`, "error"));
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
  show(state.step === "sign" ? "Il reste à signer le message de l'agent du pool." : "Connectez le portefeuille du compte qui dépose.");
}

main().catch((e) => show(`Erreur : ${e.message}`, "error"));
