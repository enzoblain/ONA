// ONA desktop window (Windows, Linux). Talks to the Rust side through Tauri commands; refreshes every second.
"use strict";

const invoke = window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);

let selected = null;      // id of the open conversation
let lastState = "";       // JSON of the last state, to redraw only on change
let lastChat = "";
let mode = "tor";
const chosenFirm = {};    // pending id → firm picked in a recipient card

const STEP_LABELS = {
  search: "Recherche", read: "Lecture d'une page", compare: "Comparaison des offres",
  confirm_recipient: "Choix du destinataire (vous)", contact: "Prise de contact",
  prepare_payment: "Préparation du paiement", confirm_payment: "Confirmation du paiement (vous)", pay: "Paiement",
};
const OUTPUT_LABELS = { search: "Recherches envoyées", fetch: "Pages lues", contact: "Messages envoyés", pay: "Paiements" };
const STATUS_LABELS = { waiting: "À confirmer", working: "En cours" };
const STATE_LABELS = { accepted: "Confirmé", rejected: "Refusé", expired: "Plus d'actualité" };

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
    toast(`Action impossible : ${error}`);
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
    $("phone-label").textContent = "Téléphone appairé";
  } else if (state.awaiting_code) {
    dot.className = "dot warn";
    $("phone-label").textContent = "Vérifiez le code";
  } else {
    dot.className = "dot";
    $("phone-label").textContent = "Appairer un téléphone";
  }
}

// Phone dialog

function drawPhone(state) {
  const body = $("phone-body");
  if (state.awaiting_code) {
    const code = state.awaiting_code;
    body.replaceChildren(
      el("h3", {}, "Code à vérifier"),
      el("p", { class: "help" }, "Le téléphone doit afficher le même code :"),
      el("div", { class: "code" }, `${code.slice(0, 3)} ${code.slice(3)}`),
      el("p", { class: "help" }, "Si les codes diffèrent, ou si le téléphone n'affiche aucun code, quelqu'un s'est peut-être interposé : refusez. Ce code expire au bout de 5 minutes."),
      el("div", { class: "card-actions actions" },
        el("button", { class: "secondary", onclick: () => run("forget_phone").then(refresh) }, "Refuser"),
        el("button", { class: "primary", onclick: () => run("confirm_code").then(refresh) }, "Les codes sont identiques")),
    );
  } else if (state.phone) {
    const date = new Date(state.phone.paired_at * 1000).toLocaleString("fr-FR");
    body.replaceChildren(
      el("h3", {}, "Téléphone appairé"),
      el("p", { class: "help" }, `Appairé le ${date}`),
      el("div", { class: "actions" }, el("button", { class: "ghost danger", onclick: forgetPhone }, "Oublier ce téléphone")),
    );
  } else if (state.qr) {
    body.replaceChildren(
      el("p", { class: "help" }, "Dans l'app ONA du téléphone, scannez ce code. Il ne sert qu'une fois."),
      el("img", { class: "qr", alt: "Code d'appairage", src: `data:image/svg+xml;charset=utf-8,${encodeURIComponent(state.qr)}` }),
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
    ? "Le serveur écoute seulement sur cet ordinateur (127.0.0.1) et est publié en service .onion par Tor."
    : "Version de développement : le serveur écoute sur le réseau local, en clair. Tout appareil de ce réseau voit les échanges.";
  $("reachable").textContent = state.reachable ? `Adresse : ${state.reachable}` : "";
  $("server-error").hidden = !state.server_error;
  $("server-error").textContent = state.server_error || "";
  $("last-request").textContent = state.last_request ? `Dernière requête du téléphone : ${state.last_request}` : "";
}

function waitingReason(state) {
  if (state.mode === "local") return "Pas d'adresse sur le réseau local.";
  switch (state.tor.state) {
    case "missing": return "Tor n'est pas installé sur cet ordinateur. Installez le paquet « tor » (Linux) ou le Tor Expert Bundle (Windows), puis rouvrez ONA.";
    case "failed": return `Tor : ${state.tor.message}`;
    case "starting": return "Publication de l'adresse .onion…";
    default: return "Tor arrêté";
  }
}

async function forgetPhone() {
  if (!await ask("Oublier ce téléphone ?", "Il ne pourra plus rien demander ni confirmer à cet ordinateur. Un nouveau code d'appairage sera créé.", "Oublier")) return;
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
    default: return el("div");
  }
}

function confirmation(pending, state) {
  const open = state === "pending";
  const footer = open
    ? el("div", { class: "actions" },
        el("button", { class: "secondary", onclick: () => decide(pending, "reject") }, "Refuser"),
        el("button", {
          class: "primary", disabled: pending.kind === "recipient" && !chosenFirm[pending.id],
          onclick: () => decide(pending, "accept"),
        }, { plan: "Valider le plan", recipient: "Contacter ce cabinet", payment: "Confirmer le paiement" }[pending.kind]))
    : el("div", { class: `state ${state}` }, STATE_LABELS[state] || state);

  let content;
  if (pending.kind === "plan") {
    content = [el("h3", {}, "Confirmation demandée"), el("ol", {}, pending.plan.map((s) => el("li", {}, STEP_LABELS[s] || s)))];
  } else if (pending.kind === "recipient") {
    content = [el("h3", {}, "Choisir le destinataire"), ...pending.offers.map((offer) => el("label", {
      class: `offer ${chosenFirm[pending.id] === offer.firm_id ? "selected" : ""}`,
    },
    el("input", {
      type: "radio", name: pending.id, disabled: !open, checked: chosenFirm[pending.id] === offer.firm_id,
      onchange: () => { chosenFirm[pending.id] = offer.firm_id; lastChat = ""; refresh(); },
    }),
    `${offer.firm_id} — ${Math.floor(offer.price_cents / 100)} €, sous ${offer.delay_days} jours`))];
  } else {
    const p = pending.payment;
    content = [
      el("h3", {}, "Paiement"),
      el("div", { class: "row" }, el("span", {}, "Montant"), el("span", {}, near(p.amount))),
      el("div", { class: "row" }, el("span", {}, "Destinataire"), el("span", { class: "mono" }, p.to)),
      el("div", { class: "sub mono" }, p.screen),
    ];
  }
  return el("div", { class: "card" }, content, footer);
}

function exposure(report) {
  const outputs = Object.entries(report.outputs || {}).sort(([a], [b]) => a.localeCompare(b));
  const firms = (report.firms_contacted || []).join(", ") || "aucun";
  return el("div", { class: "card" },
    el("h3", {}, "Relevé d'exposition"),
    el("div", { class: "sub" }, "Ce qui est sorti de cet ordinateur pendant la mission."),
    el("div", { class: "row" }, el("span", {}, "Appels au modèle"), el("span", {}, report.model_calls ?? 0)),
    outputs.map(([name, count]) => el("div", { class: "row" }, el("span", {}, OUTPUT_LABELS[name] || name), el("span", {}, count))),
    el("div", { class: "row" }, el("span", {}, "Cabinets contactés"), el("span", {}, firms)),
    (report.payments || []).map((p) => el("div", { class: "row" }, el("span", {}, "Paiement"), el("span", {}, `${near(p.amount || "0")} → ${p.to || "?"}`))),
    report.mode !== "real" ? el("div", { class: "sub" }, "Relevé d'une simulation") : null);
}

async function decide(pending, decision) {
  const args = { id: pending.id, decision, firm: null, digest: null };
  if (decision === "accept" && pending.kind === "recipient") args.firm = chosenFirm[pending.id];
  if (decision === "accept" && pending.kind === "payment") args.digest = pending.payment.digest;
  await run("confirm", args);
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
  if (!selected || !await ask("Supprimer la conversation ?", "Elle disparaît de cet ordinateur et du téléphone.", "Supprimer")) return;
  await run("delete_chat", { id: selected });
  selected = null;
  lastState = "";
  showConversation(false);
  refresh();
});

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
