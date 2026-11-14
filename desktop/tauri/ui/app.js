// ONA desktop window (Windows, Linux). Talks to the Rust side through Tauri commands; refreshes every second.
"use strict";

const invoke = window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);

let selected = null;      // id of the open conversation
let lastState = "";       // JSON of the last state, to redraw only on change
let lastChat = "";
let mode = "tor";
const chosenFirm = {};    // pending id → firm picked in a recipient card
const editedQueries = {}; // pending id → the research queries as edited here
const recipients = {};    // "chat:index" → recipient typed for a suggested action
const preparedActions = {}; // "chat:index" → the exact action from ona-core, awaiting the person's click
const doneActions = {};   // "chat:index" → what research_action_do answered

const STEP_LABELS = {
  search: "Search", read: "Read a page", compare: "Compare the offers",
  confirm_recipient: "Choose the recipient (you)", contact: "Get in touch",
  prepare_payment: "Prepare the payment", confirm_payment: "Confirm the payment (you)", pay: "Pay",
};
const OUTPUT_LABELS = {
  search: "Searches sent", fetch: "Pages read", contact: "Messages sent", pay: "Payments",
  message: "Messages handed to your mail app",
};
const STATUS_LABELS = { waiting: "To confirm", working: "Working" };
const STATE_LABELS = { accepted: "Confirmed", rejected: "Declined", expired: "No longer current" };

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (value !== undefined && value !== null && value !== false) node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function toast(message, ms = 3500) {
  const box = $("toast");
  box.textContent = message;
  box.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { box.hidden = true; }, ms);
}

let walletAccount = null; // the connected NEAR wallet's account (state.wallet_account), or null
let walletPage = null;    // "deposit" or "sign" while the wallet page holds a deposit in progress

function drawWallet(state) {
  walletAccount = state.wallet_account || null;
  walletPage = state.wallet_page || null;
  $("wallet-dot").className = walletPage ? "dot warn" : walletAccount ? "dot ok" : "dot";
  $("wallet-label").textContent = walletPage === "sign" ? "Sign in your wallet page"
    : walletPage === "deposit" ? "Deposit in your wallet page"
    : walletAccount ? `Wallet: ${walletAccount}` : "Connect wallet";
}

/**
 * A deposit is in progress on the wallet page: no other page opens meanwhile. Before it is sent it can be cancelled
 * here; once sent, only signing the agent's message on that page finishes it.
 */
async function offerCancel() {
  if (walletPage === "sign") {
    toast("Your deposit was sent: sign the pool agent's message in your wallet page to get your cash notes.", 8000);
    return false;
  }
  if (!await ask("Cancel the deposit in progress?", "Only if you did NOT confirm the deposit transaction in your wallet. If you did, go back to the wallet page and finish it there.", "Cancel the deposit")) return false;
  try {
    await run("wallet_cancel");
  } catch {
    return false;
  }
  lastState = "";
  lastChat = "";
  await refresh();
  return true;
}

/** Opens the wallet page in the browser to connect a NEAR wallet (Meteor and the others of NEAR Wallet Selector). */
async function connectWallet() {
  if (walletPage && !await offerCancel()) return;
  let url;
  try {
    url = await run("wallet_connect");
  } catch {
    return;
  }
  toast(`Your wallet page opened in the browser: choose your wallet there. If no page opened, open ${url}`, 12000);
}

async function walletButton() {
  if (walletPage) return offerCancel();
  if (!walletAccount) return connectWallet();
  if (await ask("Connected wallet", `ONA uses ${walletAccount} as the depositing account of your pool requests, and pays cash out to it only. Your wallet signs every deposit; ONA never holds its keys.`, "Connect another wallet")) {
    await connectWallet();
  }
}

/** Asks before an action that cannot be undone. Resolves to true when confirmed. */
function ask(title, text, action) {
  const dialog = $("ask-dialog");
  $("ask-title").textContent = title;
  $("ask-text").textContent = text;
  $("ask-ok").textContent = action;
  return new Promise((resolve) => {
    const done = (answer) => { dialog.close(); resolve(answer); };
    $("ask-ok").onclick = () => done(true);
    $("ask-cancel").onclick = () => done(false);
    dialog.oncancel = () => resolve(false);
    dialog.showModal();
  });
}

async function run(command, args) {
  try {
    return await invoke(command, args);
  } catch (error) {
    toast(`Could not do that: ${error}`);
    throw error;
  }
}

/** yoctoNEAR (decimal string) as NEAR, exact. */
function near(yocto) {
  const digits = yocto.padStart(25, "0");
  const whole = digits.slice(0, -24).replace(/^0+(?=\d)/, "");
  const fraction = digits.slice(-24).replace(/0+$/, "");
  return (fraction ? `${whole}.${fraction}` : whole) + " NEAR";
}

// Sidebar

function drawList(list) {
  const ul = $("chat-list");
  ul.replaceChildren(...list.chats.map((chat) => el("li", {
    class: chat.id === selected ? "selected" : "",
    onclick: () => open(chat.id),
  },
  el("span", { class: "title" }, chat.title),
  STATUS_LABELS[chat.status] ? el("span", { class: `status ${chat.status}` }, STATUS_LABELS[chat.status]) : el("span"),
  el("span", { class: "preview" }, chat.preview))));
  $("no-chats").hidden = list.chats.length > 0;
  $("mode-banner").hidden = list.mode !== "mock";
}

function drawPhoneButton(state) {
  const dot = $("phone-dot");
  if (state.phone?.verified) {
    dot.className = "dot ok";
    $("phone-label").textContent = "Phone paired";
  } else if (state.awaiting_code) {
    dot.className = "dot warn";
    $("phone-label").textContent = "Check the code";
  } else {
    dot.className = "dot";
    $("phone-label").textContent = "Pair a phone";
  }
}

// Phone dialog

function drawPhone(state) {
  const body = $("phone-body");
  if (state.awaiting_code) {
    const code = state.awaiting_code;
    body.replaceChildren(
      el("h3", {}, "Code to check"),
      el("p", { class: "help" }, "The phone must show the same code:"),
      el("div", { class: "code" }, `${code.slice(0, 3)} ${code.slice(3)}`),
      el("p", { class: "help" }, "If the codes differ, or if the phone shows no code, someone may be in the middle: decline. This code expires after 5 minutes."),
      el("div", { class: "card-actions actions" },
        el("button", { class: "secondary", onclick: () => run("forget_phone").then(refresh) }, "Decline"),
        el("button", { class: "primary", onclick: () => run("confirm_code").then(refresh) }, "The codes match")),
    );
  } else if (state.phone) {
    const date = new Date(state.phone.paired_at * 1000).toLocaleString("en-US");
    body.replaceChildren(
      el("h3", {}, "Phone paired"),
      el("p", { class: "help" }, `Paired on ${date}`),
      el("div", { class: "actions" }, el("button", { class: "ghost danger", onclick: forgetPhone }, "Forget this phone")),
    );
  } else if (state.qr) {
    body.replaceChildren(
      el("p", { class: "help" }, "Scan this code with the ONA app on the phone. It works only once."),
      el("img", { class: "qr", alt: "Pairing code", src: `data:image/svg+xml;charset=utf-8,${encodeURIComponent(state.qr)}` }),
    );
  } else {
    body.replaceChildren(el("p", { class: "help" }, waitingReason(state)));
  }

  // The local-network mode exists in development builds only.
  document.querySelector(".segmented").hidden = !state.local_mode_available;
  for (const button of document.querySelectorAll(".segmented button")) {
    button.classList.toggle("on", button.dataset.mode === state.mode);
  }
  $("mode-help").textContent = state.mode === "tor"
    ? "The server listens on this computer only (127.0.0.1) and is published as a .onion service by Tor."
    : "Development build: the server listens on the local network, unencrypted. Any device on this network sees the traffic.";
  $("reachable").textContent = state.reachable ? `Address: ${state.reachable}` : "";
  $("relay-client").hidden = !state.relay_client;
  $("relay-client-line").textContent = state.relay_client || "";
  $("server-error").hidden = !state.server_error;
  $("server-error").textContent = state.server_error || "";
  $("last-request").textContent = state.last_request ? `Last request from the phone: ${state.last_request}` : "";
}

function waitingReason(state) {
  if (state.mode === "local") return "No address on the local network.";
  switch (state.tor.state) {
    case "missing": return "Tor is not installed on this computer. Install the “tor” package (Linux) or the Tor Expert Bundle (Windows), then reopen ONA.";
    case "failed": return `Tor: ${state.tor.message}`;
    case "starting": return "Publishing the .onion address…";
    default: return "Tor stopped";
  }
}

async function forgetPhone() {
  if (!await ask("Forget this phone?", "It will no longer be able to ask or confirm anything on this computer. A new pairing code will be created.", "Forget")) return;
  await run("forget_phone");
  refresh();
}

// Conversation

function drawChat(view) {
  if (!view) {
    selected = null;
    showConversation(false);
    return;
  }
  const chat = view.chat;
  $("chat-title").textContent = chat.title;
  const items = $("items");
  const atBottom = items.scrollHeight - items.scrollTop - items.clientHeight < 40;
  items.replaceChildren(...chat.items.map(item), chat.working ? el("div", { class: "working" }, chat.working.text) : "");
  if (atBottom) items.scrollTop = items.scrollHeight;
}

function item(entry) {
  switch (entry.kind) {
    case "user": return el("div", { class: "user" }, entry.text);
    case "agent": return el("div", { class: "agent" }, entry.text);
    case "activity": return el("div", { class: "activity" }, entry.text);
    case "confirmation": return confirmation(entry.pending, entry.state);
    case "exposure": return exposure(entry.exposure);
    case "answer": return answer(entry);
    case "action": return action(entry.action, entry.state);
    case "pool": return poolCard(entry.card, entry.state);
    default: return el("div");
  }
}

// Pool requests typed in the chat ("place 1 NEAR in vault 0"): read by ONA without the model, answered here only.

const POOL_STATE_LABELS = {
  accepted: "Confirmed: the steps follow below", rejected: "Declined: nothing was sent", failed: "Stopped: see below",
};

function line(label, value) {
  return el("div", { class: "line" }, el("span", {}, label), el("span", {}, value));
}

/** "Blends in with at most N notes": an upper bound counted on the chain (docs/desktop/privacy.md). */
function blendsLine(n, where) {
  if (n === null || n === undefined) return "Privacy figure unavailable: the pool did not answer.";
  if (n <= 1) return `Your notes would be the only ones of their value ${where}: anyone watching the chain could follow them.`;
  return `${where[0].toUpperCase()}${where.slice(1)}, your notes blend in with at most ${n} notes of the same value.`;
}

function vaultName(v) {
  if (!v) return "";
  const kind = v.adapter ? ` — ${v.adapter}` : "";
  const target = v.target ? `, placed with ${v.target}` : "";
  return `Vault ${v.vault}${kind}${target}`;
}

function poolCard(c, state) {
  if (c.op === "portfolio") return chatPortfolio(c);
  if (c.op === "enter") return entryCard(c, state);
  if (["cash_enter", "switch", "leave"].includes(c.op)) return moveCard(c, state);
  const open = state === "pending";
  const deposit = c.op === "deposit";
  const title = deposit
    ? (c.vault ? `Deposit ${near(c.amount)} into vault ${c.vault.vault}` : `Deposit ${near(c.amount)} as pool cash`)
    : `Pay ${near(c.amount)} of pool cash out to your account`;
  const rows = [line("Amount", near(c.amount)), line(deposit ? "From your wallet" : "Paid to", c.account)];
  const notes = [];
  if (deposit) {
    rows.push(line("Vault", c.vault ? vaultName(c.vault) : "None: stays as cash in the pool"));
    rows.push(line("Your wallet sends", near(c.attached || "0")));
    if (c.cash_notes?.length) rows.push(line("Cash notes", c.cash_notes.map((n) => `${n.count} × ${near(n.note_value)}`).join(" + ")));
    if (c.vault && c.entry_fee) rows.push(line("Vault entry fee (storage)", near(c.entry_fee)));
    notes.push(el("p", {}, blendsLine(c.blends_with, c.vault ? `once in vault ${c.vault.vault}` : "as cash")),
      el("p", { class: "help" }, "Without ONA, a direct staking deposit is tied to your account: 1. This is an upper bound; someone who cross-checks dates and amounts can rule some notes out."));
    const recommended = (c.recommended || []).map((r) => near(r)).join(", ");
    notes.push(c.is_recommended
      ? el("p", { class: "ok-text" }, `A recommended amount (${recommended}): common amounts are harder to link to their exit.`)
      : el("p", { class: "warn" }, `Not a recommended amount. Recommended: ${recommended}. ${c.warning || ""}`));
    if (c.over_cap) notes.push(el("p", { class: "warn" }, `Above the pool's cash payout cap of ${near(c.hourly_cap)} per hour: getting this amount back out to your account will take more than one hour.`));
  } else {
    rows.push(line("You receive", near(c.received || "0")), line("Your account's exit limit", near(c.exit_limit || "0")));
    if (c.over_cap) notes.push(el("p", { class: "warn" }, `Above the pool's cash payout cap of ${near(c.hourly_cap)} per hour: the contract may refuse part of it this hour.`));
  }
  const fees = Object.entries(c.fees || {}).map(([k, v]) => line(`Fee: ${k}`, /^\d+$/.test(String(v)) ? near(String(v)) : String(v)));
  return el("div", { class: "card pool-card" },
    el("h3", {}, title),
    ...rows, ...fees, ...notes,
    el("h4", {}, open ? "If you click Yes" : "What happens"),
    el("ol", {}, (c.steps || []).map((s) => el("li", {}, s))),
    el("div", { class: "sub" }, `Network ${c.network}, contract ${c.contract}.${c.mode === "mock" ? " Simulation: fake pool." : ""}`),
    open
      ? el("div", { class: "actions" },
          el("button", { class: "secondary", onclick: () => decidePool(c.id, false, c.op) }, "No"),
          el("button", { class: "primary", onclick: () => decidePool(c.id, true, c.op) }, deposit ? "Yes, open my wallet" : "Yes, pay out"))
      : el("div", { class: `state ${state === "failed" ? "rejected" : state}` }, POOL_STATE_LABELS[state] || state));
}

/** A cash entry, a switch or a leave asked in the chat: exactly the preparation Yes runs. */
function moveCard(c, state) {
  const open = state === "pending";
  const amount = c.amount === "all" ? "All of it" : near(c.amount || "0");
  const fees = Object.entries(c.fees || {}).map(([k, v]) => line(`Fee: ${k}`, /^\d+$/.test(String(v)) ? near(String(v)) : String(v)));
  const rows = [line("Amount", amount)];
  if (c.from) rows.push(line("From", vaultName(c.from)));
  if (c.vault) rows.push(line(c.op === "switch" ? "To" : "Into", vaultName(c.vault)));
  if (c.shares_value) rows.push(line("Shares received (value)", near(c.shares_value)));
  if (c.new_shares_value) rows.push(line("New shares (value)", near(c.new_shares_value)));
  if (c.cash_value) rows.push(line("Cash notes received", near(c.cash_value)));
  if (c.share_price) rows.push(line("Share price", `${near(c.share_price)} per share`));
  rows.push(line("Left in the pool's cash (lost)", near(c.left_in_cash || "0")));
  const notes = [];
  if (c.op === "leave") {
    const live = (c.cash_live || []).map((t) => `${near(t.note_value || "0")}: ${t.live ?? "?"}`).join(", ");
    notes.push(el("p", {}, `As cash, the new notes join the cash notes in circulation of their value (${live}).`));
  } else {
    notes.push(el("p", {}, blendsLine(c.blends_with, `in vault ${c.vault?.vault}`)));
  }
  notes.push(el("p", { class: "help" }, "Without ONA, a direct staking deposit is tied to your account: 1. This is an upper bound; someone who cross-checks dates and amounts can rule some notes out."));
  if (c.over_cap) notes.push(el("p", { class: "warn" }, `Above vault ${c.from?.vault}'s exit cap of ${near(c.hourly_cap)} per hour: the leave may be spread over several hours.`));
  return el("div", { class: "card pool-card" },
    el("h3", {}, c.title),
    ...rows, ...fees, ...notes,
    el("h4", {}, open ? "If you click Yes" : "What happens"),
    el("ol", {}, (c.steps || []).map((s) => el("li", {}, s))),
    el("div", { class: "sub" }, `Network ${c.network}, contract ${c.contract}.${c.mode === "mock" ? " Simulation: fake pool." : ""}`),
    open
      ? el("div", { class: "actions" },
          el("button", { class: "secondary", onclick: () => decidePool(c.id, false, c.op) }, "No"),
          el("button", { class: "primary", onclick: () => decidePool(c.id, true, c.op) }, "Yes, do it"))
      : el("div", { class: `state ${state === "failed" ? "rejected" : state}` },
          state === "rejected" ? "Declined: nothing was sent (the notes stay reserved for up to 5 minutes)" : (POOL_STATE_LABELS[state] || state)));
}

/** The second card: the entry differs from what the first card said (money left in cash, another fee). */
function entryCard(c, state) {
  const open = state === "pending";
  const fees = Object.entries(c.fees || {}).map(([k, v]) => line(`Fee: ${k}`, /^\d+$/.test(String(v)) ? near(String(v)) : String(v)));
  return el("div", { class: "card pool-card" },
    el("h3", {}, `Put ${near(c.amount)} of cash into vault ${c.vault?.vault}?`),
    line("Vault", vaultName(c.vault)),
    line("Shares received (value)", near(c.shares_value || "0")),
    line("Left in the pool's cash (lost)", near(c.left_in_cash || "0")),
    ...fees,
    ...(c.reasons || []).map((r) => el("p", { class: "warn" }, `Differs from the first card: ${r}.`)),
    el("ol", {}, (c.steps || []).map((s) => el("li", {}, s))),
    el("div", { class: "sub" }, `Network ${c.network}, contract ${c.contract}.${c.mode === "mock" ? " Simulation: fake pool." : ""}`),
    open
      ? el("div", { class: "actions" },
          el("button", { class: "secondary", onclick: () => decidePool(c.id, false, "enter") }, "No, keep the cash"),
          el("button", { class: "primary", onclick: () => decidePool(c.id, true, "enter") }, "Yes, put it in"))
      : el("div", { class: `state ${state === "failed" ? "rejected" : state}` },
          state === "rejected" ? "Declined: the cash stays in your pool wallet" : (POOL_STATE_LABELS[state] || state)));
}

async function decidePool(card, accept, op) {
  // A deposit already waits on the wallet page: a new deposit's page would not open (payouts and entries need none).
  if (accept && op === "deposit" && walletPage && !await offerCancel()) return;
  try {
    await run("pool_card", { chat: selected, card, accept });
  } catch {
    // The reason is in the toast.
  }
  lastChat = "";
  refresh();
}

/** The portfolio asked in the chat: the same holdings as the Pool screen, read only. */
function chatPortfolio(c) {
  return el("div", { class: "card pool" },
    el("h3", {}, "Your pool portfolio"),
    el("div", { class: "total" }, near(c.portfolio.total)),
    c.mode === "mock" ? el("p", { class: "warn" }, "Simulation: fake pool (mock mode).") : null,
    ...holdings(c.portfolio, c.privacy, c.vaults_info, false));
}

function confirmation(pending, state) {
  const open = state === "pending";
  const footer = open
    ? el("div", { class: "actions" },
        el("button", { class: "secondary", onclick: () => decide(pending, "reject") }, "Decline"),
        el("button", {
          class: "primary", disabled: pending.kind === "recipient" && !chosenFirm[pending.id],
          onclick: () => decide(pending, "accept"),
        }, {
          plan: "Approve the plan", recipient: "Contact this firm", payment: "Confirm the payment",
          queries: "Run these searches",
        }[pending.kind]))
    : el("div", { class: `state ${state}` }, STATE_LABELS[state] || state);

  let content;
  if (pending.kind === "queries") {
    // Editable here only; the phone accepts them as shown. An emptied field is dropped.
    const shown = editedQueries[pending.id] || pending.queries;
    content = [
      el("h3", {}, "Searches to run"),
      el("div", { class: "sub" }, "Nothing goes out to the web before you approve. These searches will go through Tor, exactly as written here."),
      el("div", { class: "queries" }, shown.map((query, i) => open
        ? el("input", {
            class: "field", value: query, maxlength: 120, "aria-label": `Search ${i + 1}`,
            oninput: (event) => {
              const list = [...(editedQueries[pending.id] || pending.queries)];
              list[i] = event.target.value;
              editedQueries[pending.id] = list;
            },
          })
        : el("div", { class: "query" }, `“${query}”`))),
    ];
  } else if (pending.kind === "plan") {
    content = [el("h3", {}, "Confirmation needed"), el("ol", {}, pending.plan.map((s) => el("li", {}, STEP_LABELS[s] || s)))];
  } else if (pending.kind === "recipient") {
    content = [el("h3", {}, "Choose the recipient"), ...pending.offers.map((offer) => el("label", {
      class: `offer ${chosenFirm[pending.id] === offer.firm_id ? "selected" : ""}`,
    },
    el("input", {
      type: "radio", name: pending.id, disabled: !open, checked: chosenFirm[pending.id] === offer.firm_id,
      onchange: () => { chosenFirm[pending.id] = offer.firm_id; lastChat = ""; refresh(); },
    }),
    `${offer.firm_id} — €${Math.floor(offer.price_cents / 100)}, within ${offer.delay_days} ${offer.delay_days === 1 ? "day" : "days"}`))];
  } else {
    const p = pending.payment;
    content = [
      el("h3", {}, "Payment"),
      el("div", { class: "row" }, el("span", {}, "Amount"), el("span", {}, near(p.amount))),
      el("div", { class: "row" }, el("span", {}, "Recipient"), el("span", { class: "mono" }, p.to)),
      el("div", { class: "sub mono" }, p.screen),
    ];
  }
  return el("div", { class: "card" }, content, footer);
}

function exposure(report) {
  const outputs = Object.entries(report.outputs || {}).sort(([a], [b]) => a.localeCompare(b));
  // A research contacts no firm: the row is shown for the lawyer mission's reports only.
  const firms = (report.firms_contacted || []).join(", ");
  return el("div", { class: "card" },
    el("h3", {}, "Exposure report"),
    el("div", { class: "sub" }, "What left this computer during the mission."),
    el("div", { class: "row" }, el("span", {}, "Model calls"), el("span", {}, report.model_calls ?? 0)),
    outputs.map(([name, count]) => el("div", { class: "row" }, el("span", {}, OUTPUT_LABELS[name] || name), el("span", {}, count))),
    firms ? el("div", { class: "row" }, el("span", {}, "Firms contacted"), el("span", {}, firms)) : null,
    (report.payments || []).map((p) => el("div", { class: "row" }, el("span", {}, "Payment"), el("span", {}, `${near(p.amount || "0")} → ${p.to || "?"}`))),
    report.mode !== "real" ? el("div", { class: "sub" }, "Report from a simulation") : null);
}

async function decide(pending, decision) {
  const args = { id: pending.id, decision, firm: null, digest: null };
  if (decision === "accept" && pending.kind === "recipient") args.firm = chosenFirm[pending.id];
  if (decision === "accept" && pending.kind === "payment") args.digest = pending.payment.digest;
  if (decision === "accept" && pending.kind === "queries") {
    args.queries = (editedQueries[pending.id] || pending.queries).map((q) => q.trim()).filter(Boolean);
    if (args.queries.length === 0) return toast("Keep at least one search.");
  }
  await run("confirm", args);
  lastChat = "";
  refresh();
}

/** The host of an address, shown next to a source; the address itself is text, never a link. */
function hostOf(url) {
  try {
    return new URL(url).host;
  } catch {
    return "";
  }
}

function answer(entry) {
  const titles = Object.fromEntries((entry.sources || []).map((s) => [s.handle, s.title]));
  const notes = entry.notes || [];
  return el("div", { class: "card answer" },
    el("h3", {}, "Answer"),
    el("p", { class: "answer-text" }, entry.answer),
    notes.length ? el("h4", {}, "From the pages read") : null,
    notes.length ? el("ul", { class: "notes" }, notes.map((n) => el("li", {},
      el("div", {}, n.claim),
      el("div", { class: "quote" }, `“${n.quote}”`),
      el("div", { class: "sub" }, `Source ${n.source}${titles[n.source] ? ` — ${titles[n.source]}` : ""}`)))) : null,
    el("h4", {}, "Sources"),
    (entry.sources || []).length
      ? el("ol", { class: "sources" }, entry.sources.map((s) => el("li", {},
          el("div", {}, `${s.handle} — ${s.title}`, el("span", { class: "sub" }, `  ${hostOf(s.url)}`)),
          el("div", { class: "mono" }, s.url))))
      : el("div", { class: "sub" }, "No source read."),
    el("div", { class: "sub" }, "Addresses are shown for information only: ONA does not open them."));
}

/** A suggested action: the person types the recipient, sees the exact action, then carries it out here. */
function action(a, state) {
  const key = `${selected}:${a.index}`;
  const isMessage = a.kind === "message";
  const card = el("div", { class: "card action" },
    el("h3", {}, isMessage ? "Suggested message" : "Suggested payment"),
    el("div", { class: "sub" }, a.purpose),
    isMessage ? el("div", { class: "message-text" }, a.text)
      : el("div", { class: "row" }, el("span", {}, "Amount"), el("span", {}, near(a.amount || "0"))));
  const done = doneActions[key];
  if (state === "done") {
    card.append(el("div", { class: "state accepted" }, isMessage ? "Handed to your mail app" : "Paid"));
    if (done?.done === "message" && !done.opened) {
      card.append(el("p", { class: "help" }, "Your mail app did not open. Address to copy into your mail app:"),
        el("div", { class: "mono" }, done.mailto));
    }
    if (done?.done === "payment") card.append(el("div", { class: "sub mono" }, `Transaction: ${done.tx}`));
    return card;
  }
  const prepared = preparedActions[key];
  if (prepared) {
    card.append(...[
      el("h4", {}, "Exact action"),
      el("div", { class: "row" }, el("span", {}, "Recipient"), el("span", { class: "mono" }, prepared.to)),
      prepared.kind === "message"
        ? el("div", { class: "message-text" }, prepared.content)
        : el("div", { class: "row" }, el("span", {}, "Amount"), el("span", {}, near(prepared.content))),
      prepared.seen_in_pages
        ? el("p", { class: "warn" }, "This address appears in a page that was read: check that it is the right one.")
        : null,
      prepared.kind === "message"
        ? el("p", { class: "help" }, "The message opens in your mail app: you are the one who sends it.")
        : null,
      el("div", { class: "actions" },
        el("button", { class: "secondary", onclick: () => { delete preparedActions[key]; lastChat = ""; refresh(); } }, "Edit"),
        el("button", { class: "primary", onclick: () => doAction(key, prepared) },
          prepared.kind === "message" ? "Send from my mail app" : "Pay")),
    ].filter(Boolean));
    return card;
  }
  const input = el("input", {
    class: "field", value: recipients[key] || "",
    placeholder: isMessage ? "Recipient email address" : "Recipient NEAR account (name.testnet)",
    "aria-label": "Recipient",
    oninput: (event) => { recipients[key] = event.target.value; },
  });
  card.append(el("label", { class: "recipient" }, "Recipient", input),
    el("div", { class: "actions" },
      el("button", { class: "primary", onclick: () => prepareAction(key, a.index) }, "Prepare")));
  return card;
}

async function prepareAction(key, index) {
  const to = (recipients[key] || "").trim();
  if (!to) return toast("Enter the recipient.");
  try {
    const prepared = await run("research_action_prepare", { chat: selected, index, to });
    // ona-core holds one prepared action at a time: another one shown for this chat would no longer match.
    for (const other of Object.keys(preparedActions)) if (other.startsWith(`${selected}:`)) delete preparedActions[other];
    preparedActions[key] = prepared;
  } catch {
    return; // the reason is in the toast
  }
  lastChat = "";
  refresh();
}

async function doAction(key, prepared) {
  try {
    doneActions[key] = await run("research_action_do", { chat: selected, digest: prepared.digest });
  } catch {
    // The reason is in the toast; the action is prepared again from the start.
  }
  delete preparedActions[key];
  lastChat = "";
  refresh();
}

function showConversation(shown) {
  $("conversation").hidden = !shown;
  $("welcome").hidden = shown;
}

function open(id) {
  selected = id;
  lastChat = "";
  lastState = "";
  showConversation(true);
  refresh();
}

// Refresh loop

async function refresh() {
  let state;
  try {
    state = await invoke("state");
  } catch {
    return;
  }
  const text = JSON.stringify(state);
  if (text !== lastState) {
    lastState = text;
    mode = state.mode;
    drawList(state.chats);
    drawWallet(state);
    drawPhoneButton(state);
    drawPhone(state);
  }
  if (selected) {
    const view = await invoke("chat", { id: selected }).catch(() => null);
    const chatText = JSON.stringify(view);
    if (chatText !== lastChat) {
      lastChat = chatText;
      drawChat(view);
    }
  }
}

// Events

$("composer").addEventListener("submit", async (event) => {
  event.preventDefault();
  const text = $("text").value.trim();
  if (!text) return;
  $("send").disabled = true;
  try {
    if (selected) {
      await run("post_message", { id: selected, text });
    } else {
      const id = await run("create_chat", { text });
      selected = id;
      showConversation(true);
    }
    $("text").value = "";
    lastState = "";
    lastChat = "";
    await refresh();
  } finally {
    $("send").disabled = false;
    $("text").focus();
  }
});

$("text").addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
    event.preventDefault();
    $("composer").requestSubmit();
  }
});

$("new-chat").addEventListener("click", () => {
  selected = null;
  lastState = "";
  showConversation(false);
  refresh();
  $("text").focus();
});

$("delete-chat").addEventListener("click", async () => {
  if (!selected || !await ask("Delete the conversation?", "It disappears from this computer and from the phone.", "Delete")) return;
  await run("delete_chat", { id: selected });
  selected = null;
  lastState = "";
  showConversation(false);
  refresh();
});

// Pool dialog (docs/desktop/pool-commands.md). Every operation: prepare, show the summary, confirm here, execute.

const POOL_OPS = {
  enter: "Put cash into a vault",
  switch: "Switch vaults",
  exit: "Leave a vault (to cash)",
  exit_cash: "Pay cash out to an account",
  deposit: "Deposit from a NEAR wallet",
};
const SUMMARY_LABELS = {
  amount: "Amount", vault: "Vault", from: "From vault", to: "To", shares_value: "Shares received (value)",
  new_shares_value: "New shares (value)", cash_value: "Cash received", received: "Received", left_in_cash: "Left in the pool's cash (lost)",
  exit_limit: "Account exit limit", account: "Account",
};
const NOT_AMOUNTS = new Set(["vault", "from", "to", "account"]);

async function pool(request) {
  const reply = await run("pool", { request });
  if (reply.ok !== true) throw new Error(reply.error || "pool error");
  return reply;
}

/** "1.5" NEAR as yoctoNEAR (decimal string), exact; null when not a number. */
function yocto(text) {
  const match = /^\s*(\d+)(?:[.,](\d{0,24}))?\s*$/.exec(text);
  if (!match) return null;
  return (BigInt(match[1]) * 10n ** 24n + BigInt((match[2] || "").padEnd(24, "0"))).toString();
}

async function openPool() {
  $("pool-dialog").showModal();
  await drawPortfolio();
}

let poolInfo = null; // the last pool_info reply (vault kinds, recommended deposits), for the forms

/** The wallet line at the top of the Pool screen: the connected account, or a button to connect one. */
function walletRow() {
  return el("div", { class: "wallet-row" },
    el("span", { class: "who" }, walletAccount
      ? [el("span", { class: "help" }, "Wallet  "), el("span", { class: "mono" }, walletAccount)]
      : el("span", { class: "help" }, "No NEAR wallet connected: deposits need one (Meteor, for example).")),
    el("button", { class: walletAccount ? "secondary" : "primary", onclick: connectWallet }, walletAccount ? "Connect another" : "Connect wallet"),
    walletAccount ? el("button", { class: "ghost", onclick: forgetWallet }, "Forget") : null);
}

async function forgetWallet() {
  try {
    await run("wallet_forget");
  } catch {
    return;
  }
  lastState = "";
  await refresh();
  drawPortfolio();
}

/** The smallest set among the held notes of one place (`null`: cash), from pool_privacy's notes. */
function placeSet(privacy, vault) {
  const sets = (privacy?.wallet?.notes || []).filter((n) => (n.vault ?? null) === vault).map((n) => n.set);
  return sets.length ? Math.min(...sets) : null;
}

/**
 * The holdings, as the phone's Pool tab shows them (total, cash, one line per vault, frozen, operation in progress),
 * plus the notes per tier, the vault's kind and target, each holding's privacy figure and what can be withdrawn.
 * `actions`: the Pool screen's buttons (not in the chat's read-only card).
 */
function holdings(portfolio, privacy, infoVaults, actions) {
  const cash = portfolio.cash;
  const cashPending = cash.spending_value !== "0" || cash.awaiting_signature > 0;
  const cashSet = placeSet(privacy, null);
  const tierLine = (t, unit) => line(`${t.held} × ${near(t.note_value)}${unit}`,
    t.spending ? `${t.spending} in an operation in progress` : "held");
  const cashCard = el("div", { class: "holding-card" },
    el("div", { class: "holding-head" }, el("span", { class: "name" }, "Cash"), el("span", { class: "value" }, near(cash.value)),
      actions ? el("button", { class: "secondary", onclick: () => poolForm("enter", portfolio, undefined, privacy) }, "Put in a vault") : null,
      actions ? el("button", { class: "secondary", onclick: () => poolForm("exit_cash", portfolio) }, "Pay out") : null),
    (cash.tiers || []).length ? cash.tiers.map((t) => tierLine(t, " cash notes")) : el("div", { class: "help" }, "No cash notes."),
    cashPending ? line("Operation in progress", `${near(cash.spending_value)} moving, ${cash.awaiting_signature} awaiting the agent's signature`) : null,
    cashSet !== null ? el("div", { class: "help" }, blendsLine(cashSet, "as cash")) : null,
    cash.value !== "0" ? line("Can be withdrawn", `${near(cash.value)} to the account that deposited (its exit limit is checked when you prepare)`) : null);
  const vaultCards = (portfolio.vaults || []).map((v) => {
    const info = (infoVaults || []).find((i) => i.vault === v.vault);
    const pending = v.spending_value !== "0" || v.awaiting_signature > 0;
    const set = placeSet(privacy, v.vault);
    const shares = (t) => {
      const each = info?.tiers?.[t.tier]?.note_shares;
      return each ? ` (${BigInt(each) * BigInt(t.held)} shares)` : "";
    };
    return el("div", { class: "holding-card" },
      el("div", { class: "holding-head" },
        el("span", { class: "name" }, info ? vaultName(info) : `Vault ${v.vault}`, v.frozen ? " (frozen)" : ""),
        el("span", { class: "value" }, near(v.value)),
        actions ? el("button", { class: "secondary", onclick: () => poolForm("switch", portfolio, v.vault) }, "Switch") : null,
        actions ? el("button", { class: "secondary", onclick: () => poolForm("exit", portfolio, v.vault) }, "Leave") : null),
      (v.tiers || []).map((t) => line(`${t.held} share notes of ${near(t.note_value)}${shares(t)}`,
        t.spending ? `${t.spending} in an operation in progress` : "held")),
      line("Share price", `${near(v.share_price)} per share`),
      pending ? line("Operation in progress", `${near(v.spending_value)} moving, ${v.awaiting_signature} awaiting the agent's signature`) : null,
      set !== null ? el("div", { class: "help" }, blendsLine(set, `in vault ${v.vault}`)) : null,
      line("To withdraw", "Leave the vault first (shares become cash notes), then pay the cash out"));
  });
  return [el("div", { class: "section" }, el("h4", {}, "Your holdings"), cashCard, ...vaultCards)];
}

/** Every vault the pool lists, with or without your notes: kind, target, price, state, and what an entry would hide. */
function vaultsSection(info, privacy) {
  const byVault = new Map((privacy?.vaults || []).map((v) => [v.vault, v]));
  return el("div", { class: "section" }, el("h4", {}, "Vaults in the pool"),
    (info.vaults || []).length ? info.vaults.map((v) => {
      const p = byVault.get(v.vault);
      const live = (v.tiers || []).map((t) => t.live).filter((n) => n !== null && n !== undefined);
      return el("div", { class: "holding-card" },
        el("div", { class: "holding-head" }, el("span", { class: "name" }, vaultName(v)),
          el("span", { class: "help" }, v.frozen ? "Frozen: takes no new money" : "Open")),
        line("Share price", `${near(v.share_price)} per share`),
        (v.tiers || []).length ? line("Share notes", v.tiers.map((t) => near(t.note_value)).join(", ")) : null,
        live.length ? line("Notes in circulation", live.join(" / ")) : null,
        v.hourly_cap ? line("Exit cap per hour", near(v.hourly_cap)) : null,
        p?.if_entered !== undefined ? el("div", { class: "help" }, `Putting your cash in: your notes would blend in with at most ${p.if_entered} notes${p.gain !== undefined ? ` (${p.gain >= 0 ? "+" : ""}${p.gain} compared with your cash)` : ""}.`) : null);
    }) : el("div", { class: "help" }, "The pool lists no vault."));
}

function offerSection(info) {
  return el("div", { class: "section" }, el("h4", {}, "Deposits"),
    line("Recommended amounts", (info.recommended || []).map((r) => near(r)).join(", ") || "none"),
    line("Smallest deposit", near(info.min_deposit || "0")),
    line("Cash notes", (info.cash?.tiers || []).map((t) => near(t.note_value || "0")).join(", ")),
    info.cash?.hourly_cap ? line("Cash payouts per hour (all accounts)", `at most ${near(info.cash.hourly_cap)}`) : null,
    el("p", { class: "help" }, "A common amount is harder to link to its exit. Your wallet sends and signs every deposit."),
    el("p", { class: "help" }, `Network ${info.network}, contract ${info.contract}.`));
}

function retryCard(what, error) {
  return el("div", { class: "card" },
    el("p", { class: "error" }, `${what}: ${error}`),
    el("p", { class: "help" }, "The pool is set up with pool.json in the app folder, and is reached through Tor once the QR code shows in the Phone window (see docs/desktop/tauri.md)."),
    el("div", { class: "card-actions actions" }, el("button", { class: "primary", onclick: drawPortfolio }, "Retry")));
}

/** Sets the Pool screen's content; null entries are left out (replaceChildren would write them as "null"). */
function setPoolBody(...nodes) {
  $("pool-body").replaceChildren(...nodes.flat().filter((n) => n !== null && n !== undefined && n !== false));
}

/** The essentials: one line per holding, its value, its privacy figure, an operation in progress. */
function compactHoldings(portfolio, privacy, infoVaults) {
  const row = (name, value, set, where, pending, ...buttons) => el("div", { class: "holding-card" },
    el("div", { class: "holding-head" }, el("span", { class: "name" }, name, pending ? el("span", { class: "help" }, "  · operation in progress") : null),
      el("span", { class: "value" }, near(value)), ...buttons),
    set !== null ? el("div", { class: "help" }, blendsLine(set, where)) : null);
  const cash = portfolio.cash;
  return [
    row("Cash", cash.value, placeSet(privacy, null), "as cash", cash.spending_value !== "0" || cash.awaiting_signature > 0),
    ...(portfolio.vaults || []).map((v) => {
      const info = (infoVaults || []).find((i) => i.vault === v.vault);
      return row(`${info ? vaultName(info) : `Vault ${v.vault}`}${v.frozen ? " (frozen)" : ""}`, v.value, placeSet(privacy, v.vault),
        `in vault ${v.vault}`, v.spending_value !== "0" || v.awaiting_signature > 0,
        el("button", { class: "secondary", onclick: () => poolForm("switch", portfolio, v.vault) }, "Switch"),
        el("button", { class: "secondary", onclick: () => poolForm("exit", portfolio, v.vault) }, "Leave"));
    }),
  ];
}

async function drawPortfolio() {
  setPoolBody(walletRow(), el("p", { class: "help" }, "Reading the pool…"));
  // Read together; each part is shown if it came, with its exact error otherwise.
  const [p, v, i] = await Promise.allSettled([
    pool({ cmd: "pool_portfolio" }), pool({ cmd: "pool_privacy" }), pool({ cmd: "pool_info" }),
  ]);
  const reason = (r) => r.reason?.message || String(r.reason);
  const privacy = v.status === "fulfilled" ? v.value : null;
  const info = i.status === "fulfilled" ? i.value : null;
  poolInfo = info;
  if (p.status !== "fulfilled") {
    setPoolBody(walletRow(), retryCard("Pool unavailable", reason(p)),
      info ? el("details", {}, el("summary", {}, "Details"), offerSection(info)) : null);
    return;
  }
  const portfolio = p.value;
  // Top: the essentials. Everything else in "Details", closed.
  setPoolBody(
    walletRow(),
    el("div", {}, el("p", { class: "help" }, "Total value"), el("div", { class: "total" }, near(portfolio.total))),
    portfolio.mode === "mock" ? el("p", { class: "warn" }, "Simulation: fake pool (mock mode).") : null,
    el("div", { class: "section" }, ...compactHoldings(portfolio, privacy, info?.vaults)),
    privacy ? null : el("p", { class: "help" }, `Privacy figures unavailable: ${reason(v)}`),
    el("div", { class: "ops" },
      el("button", { class: "primary", onclick: () => poolForm("deposit", portfolio) }, "Deposit"),
      el("button", { class: "secondary", onclick: () => poolForm("enter", portfolio, undefined, privacy) }, "Put cash in a vault"),
      el("button", { class: "secondary", onclick: () => poolForm("exit_cash", portfolio) }, "Withdraw")),
    el("p", { class: "help" }, "You can also ask in the chat: “how much do I have?”, “put my cash in vault 0”, “withdraw 0.5 NEAR”."),
    el("details", { class: "details" }, el("summary", {}, "Details"),
      privacy ? privacyCard(privacy) : null,
      ...holdings(portfolio, privacy, info?.vaults, false),
      info ? vaultsSection(info, privacy) : el("p", { class: "help" }, `Vault details unavailable: ${reason(i)}`),
      info ? offerSection(info) : null,
      el("div", { class: "ops" }, el("button", { class: "secondary", onclick: recover }, "Recover pending operations")),
      el("p", { class: "help" }, `Read at ${new Date().toLocaleTimeString("en-US")}. Values at the contract's public prices; held notes only.`)),
  );
}

/** "Among at most N": a measured upper bound, never a percentage (docs/desktop/privacy.md). */
function privacyCard(p) {
  const smallest = p.wallet.smallest_set;
  const line = smallest === null || smallest === undefined
    ? "No notes in the pool yet."
    : smallest <= 1
      ? "Your least protected note is the only one of its value in its place: anyone watching the chain can follow it."
      : `Your least protected note blends in with at most ${smallest} notes of the same value in the same place.`;
  return el("div", { class: "card privacy" },
    el("h3", {}, "Privacy"),
    el("p", {}, line),
    el("p", { class: "help" }, `Without ONA, a direct staking deposit is tied to your account: 1. These are upper bounds, counted on the chain; someone who cross-checks dates and amounts can rule some notes out.`));
}

/** "+ X" next to a vault: how many more notes an entry would hide among than the cash it spends. */
function gainLabel(v) {
  if (v.if_entered === undefined) return "";
  const gain = v.gain === undefined ? "" : v.gain >= 0 ? `, +${v.gain}` : `, ${v.gain}`;
  return ` — among ${v.if_entered} notes${gain}`;
}

/** The form of one operation; on submit, `pool_prepare`, then the summary to confirm. */
function poolForm(op, portfolio, vault, privacy) {
  const byVault = new Map((privacy?.vaults || []).map((v) => [v.vault, v]));
  const vaultOptions = (except) => Array.from({ length: portfolio.vault_count || 0 }, (_, i) => i)
    .filter((i) => i !== except)
    .map((i) => el("option", { value: i }, `Vault ${i}${op === "enter" && byVault.has(i) ? gainLabel(byVault.get(i)) : ""}`));
  const amountField = (label, all) => el("label", {}, label,
    el("input", { name: "amount", placeholder: all ? "in NEAR, or “all”" : "in NEAR", required: true }));
  const fields = {
    enter: [el("label", {}, "Vault", el("select", { name: "vault" }, vaultOptions())), amountField("Cash to put in", true)],
    switch: [el("label", {}, "To vault", el("select", { name: "to" }, vaultOptions(vault))), amountField(`Shares of vault ${vault} to move`, true)],
    exit: [amountField(`Shares of vault ${vault} to turn into cash`, true)],
    exit_cash: [el("label", {}, "NEAR account that deposited (the contract pays no other)", el("input", { name: "to", placeholder: "name.testnet", value: walletAccount || "", required: true })), amountField("Cash to pay", false)],
    deposit: [el("label", {}, "Your NEAR account (the connected wallet)", el("input", { name: "account", placeholder: "name.testnet", value: walletAccount || "", required: true })), amountField("Amount to deposit", false)],
  }[op];
  // Deposit: the recommended amounts, one click each (a common amount is harder to link to its exit).
  const chips = op === "deposit" && poolInfo?.recommended?.length
    ? el("div", { class: "chips" }, el("span", { class: "help" }, "Recommended:"), poolInfo.recommended.map((r) => el("button", {
        type: "button", class: "chip",
        onclick: () => { form.querySelector("input[name=amount]").value = near(r).replace(" NEAR", ""); },
      }, near(r))))
    : null;
  const form = el("form", {}, el("h3", {}, POOL_OPS[op]), ...fields, chips,
    el("div", { class: "card-actions actions" },
      el("button", { type: "button", class: "secondary", onclick: drawPortfolio }, "Cancel"),
      el("button", { type: "submit", class: "primary" }, "Prepare")));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(form));
    const request = { cmd: "pool_prepare", op };
    if (data.amount !== undefined) {
      const all = /^\s*(tout|all)\s*$/i.test(data.amount);
      const amount = all ? "all" : yocto(data.amount);
      if (!amount) return toast("Unreadable amount: write for example 1.5");
      request.amount = amount;
    }
    if (op === "enter") request.vault = Number(data.vault);
    if (op === "switch") { request.from = vault; request.to = Number(data.to); }
    if (op === "exit") request.from = vault;
    if (op === "exit_cash") request.to = data.to.trim();
    if (op === "deposit") request.account = data.account.trim();
    try {
      showSummary(await pool(request));
    } catch (error) {
      toast(`Preparation refused: ${error.message}`);
    }
  });
  $("pool-body").replaceChildren(form);
}

function summaryRows(summary) {
  return Object.entries(SUMMARY_LABELS).filter(([key]) => summary[key] !== undefined).map(([key, label]) =>
    el("div", { class: "row" }, el("span", {}, label),
      el("span", {}, NOT_AMOUNTS.has(key) ? String(summary[key]) : near(String(summary[key])))));
}

/** What will be done, from ona-core's summary; executed only once the person confirms here. */
function showSummary(prepared) {
  const summary = prepared.summary;
  const fees = Object.entries(summary.fees || {}).map(([key, value]) =>
    el("div", { class: "row" }, el("span", {}, `Fee: ${key}`), el("span", {}, /^\d+$/.test(String(value)) ? near(String(value)) : String(value))));
  const warnings = [summary.warning, ...(summary.warnings || [])].filter(Boolean).map((w) => el("p", { class: "warn" }, w));
  const expires = new Date(Number(BigInt(summary.expires_at) / 1000000n)).toLocaleTimeString("en-US");
  const card = el("div", { class: "card" }, el("h3", {}, POOL_OPS[summary.op] || summary.op),
    ...summaryRows(summary), ...fees, ...warnings,
    el("p", { class: "help" }, `Network ${summary.network}, contract ${summary.contract}. Valid until ${expires}.`));
  if (summary.op === "deposit") {
    // Sent and signed by the person's own NEAR wallet, on a page the app opens in the browser (docs/desktop/wallet.md).
    card.append(el("p", { class: "help" }, "Your NEAR wallet sends this deposit, then signs a message for the pool agent. ONA never sees its keys."),
      el("div", { class: "card-actions actions" },
        el("button", { class: "secondary", onclick: drawPortfolio }, "Cancel"),
        el("button", { class: "primary", onclick: () => openWallet(prepared) }, "Open my wallet")));
  } else {
    card.append(el("div", { class: "card-actions actions" },
      el("button", { class: "secondary", onclick: drawPortfolio }, "Cancel"),
      el("button", { class: "primary", onclick: () => execute(prepared.prepared_id) }, "Confirm")));
  }
  $("pool-body").replaceChildren(card);
}

/** Opens the wallet page in the browser; the deposit then goes on there. */
async function openWallet(prepared) {
  if (walletPage && !await offerCancel()) return;
  let url;
  try {
    url = await run("wallet_open", { prepared });
  } catch {
    return;
  }
  $("pool-body").replaceChildren(el("div", { class: "card" },
    el("h3", {}, "Deposit in progress in your browser"),
    el("p", { class: "help" }, "Your wallet page has opened. If it has not, open this address in your browser:"),
    el("p", { class: "mono" }, url),
    el("p", { class: "help" }, "Once the page is done, refresh: the notes appear when the pool agent has issued them."),
    el("div", { class: "card-actions actions" }, el("button", { class: "primary", onclick: drawPortfolio }, "Refresh"))));
}

async function execute(preparedId) {
  try {
    const reply = await pool({ cmd: "pool_execute", prepared_id: preparedId });
    toast(reply.complete ? "Operation done." : "Operation partly done: see the steps.");
  } catch (error) {
    // Entries, exits and cash payments are queued by the pool agent: their outcome comes later through pool_recover.
    if (/outcome unknown/.test(error.message)) toast("Sent to the pool agent: the result will come later (Recover).");
    else toast(`Operation refused: ${error.message}`);
  }
  await drawPortfolio();
}

async function recover() {
  try {
    const r = await pool({ cmd: "pool_recover" });
    toast(`Recovery: ${r.spent} done, ${r.held_again} returned, ${r.still_spending} pending${r.agent_error ? ` (agent: ${r.agent_error})` : ""}.`);
  } catch (error) {
    toast(`Could not recover: ${error.message}`);
  }
  await drawPortfolio();
}

$("pool-button").addEventListener("click", openPool);
$("refresh-pool").addEventListener("click", drawPortfolio);
$("wallet-button").addEventListener("click", walletButton);
$("close-pool").addEventListener("click", () => $("pool-dialog").close());
$("phone-button").addEventListener("click", () => $("phone-dialog").showModal());
$("close-phone").addEventListener("click", () => $("phone-dialog").close());
for (const button of document.querySelectorAll(".segmented button")) {
  button.addEventListener("click", async () => {
    if (button.dataset.mode === mode) return;
    await run("set_mode", { mode: button.dataset.mode });
    lastState = "";
    refresh();
  });
}

refresh();
setInterval(refresh, 1000);
