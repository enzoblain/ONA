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

function toast(message) {
  const box = $("toast");
  box.textContent = message;
  box.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { box.hidden = true; }, 3500);
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
    default: return el("div");
  }
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

async function drawPortfolio() {
  const body = $("pool-body");
  body.replaceChildren(el("p", { class: "help" }, "Reading the pool…"));
  let portfolio;
  try {
    portfolio = await pool({ cmd: "pool_portfolio" });
  } catch (error) {
    body.replaceChildren(el("p", { class: "error" }, `Pool unavailable: ${error.message}`),
      el("p", { class: "help" }, "The pool is set up with pool.json in the app folder (see docs/desktop/tauri.md)."));
    return;
  }
  // The privacy figures (docs/desktop/privacy.md): read with the portfolio, shown only if the pool answers.
  const privacy = await pool({ cmd: "pool_privacy" }).catch(() => null);
  const holding = (name, value, pending, ...buttons) => el("div", { class: "holding" },
    el("span", { class: "name" }, name, pending ? el("span", { class: "help" }, "  · operation in progress") : null),
    el("span", { class: "value" }, near(value)), ...buttons);
  const vaults = portfolio.vaults || [];
  body.replaceChildren(
    el("div", {}, el("p", { class: "help" }, "Total value"), el("div", { class: "total" }, near(portfolio.total))),
    portfolio.mode === "mock" ? el("p", { class: "warn" }, "Simulation: fake pool (mock mode).") : null,
    privacy ? privacyCard(privacy) : null,
    el("div", {},
      holding("Cash", portfolio.cash.value, portfolio.cash.spending_value !== "0"),
      ...vaults.map((v) => holding(`Vault ${v.vault}${v.frozen ? " (frozen)" : ""}`, v.value,
        v.spending_value !== "0" || v.awaiting_signature > 0,
        el("button", { class: "secondary", onclick: () => poolForm("switch", portfolio, v.vault) }, "Switch"),
        el("button", { class: "secondary", onclick: () => poolForm("exit", portfolio, v.vault) }, "Leave")))),
    el("div", { class: "ops" },
      el("button", { class: "primary", onclick: () => poolForm("enter", portfolio, undefined, privacy) }, "Put cash in"),
      el("button", { class: "secondary", onclick: () => poolForm("exit_cash", portfolio) }, "Pay to an account"),
      el("button", { class: "secondary", onclick: () => poolForm("deposit", portfolio) }, "Deposit"),
      el("button", { class: "secondary", onclick: recover }, "Recover pending operations")),
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
    exit_cash: [el("label", {}, "NEAR account that deposited", el("input", { name: "to", placeholder: "name.testnet", required: true })), amountField("Cash to pay", false)],
    deposit: [el("label", {}, "Your NEAR account", el("input", { name: "account", placeholder: "name.testnet", required: true })), amountField("Amount to deposit", false)],
  }[op];
  const form = el("form", {}, el("h3", {}, POOL_OPS[op]), ...fields,
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
