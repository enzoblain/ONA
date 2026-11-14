import { useEffect, useMemo, useRef, useState } from "react";
import { motion } from "motion/react";
import NumberFlow from "@number-flow/react";
import { EASE, REPO } from "../components/Layout";
import { Reveal } from "../components/Reveal";
import demo from "../data/demo.json";

// ---------- Mission replay: the recorded output of `ona demo` (src/data/demo.json) ----------

type Json = Record<string, any>;
type Step = { send: Json; reply: Json };
type Party = { party: string; kind: string; requests: number; bytes_sent: number };

const steps = demo.steps as Step[];
const report = steps[steps.length - 1].reply;
const parties = report.parties as Party[];

const euros = (cents: number) => `${(cents / 100).toLocaleString("en-GB")} euros`;

// What each command means, in words. Figures are read from the recorded reply, never typed here.
const explain: Record<string, (s: Step) => [string, string, string]> = {
  open: (s) => ["You", "Open the mission", `One protected term is declared: ${s.send.protected.join(", ")}. It is replaced by a pseudonym before any text goes to the model.`],
  propose_plan: (s) => ["Agent", "The agent proposes a plan", `${s.reply.plan.length} steps. Choosing the firm and paying each need your confirmation.`],
  accept_plan: () => ["You", "You accept the plan", "Nothing runs before this."],
  search: (s) => ["Agent", `Search for a ${s.send.template} in ${s.send.value}`, `The search is a template and a value, not free text from your case. ${s.reply.handles.length} results come back.`],
  read: (s) => {
    const o = s.reply.offer;
    return ["Agent", `Read the offer of ${o.firm_id}`, `${euros(o.price_cents)}, within ${o.delay_days} days. The quoted line of the page is kept as the source: “${o.source_spans[0]}”.`];
  },
  compare: (s) => ["Agent", "Compare the offers", `${s.reply.ranked[0].firm_id} comes first at ${euros(s.reply.ranked[0].price_cents)}.`],
  confirm_recipient: (s) => ["You", `You choose ${s.send.firm}`, "Only the firm you pick gets a message."],
  contact: (s) => ["Agent", "Contact the firm", `A generic message, with no name in it: “${s.send.message}”`],
  prepare_payment: (s) => ["Agent", `Prepare a payment of ${s.reply.amount_near} NEAR`, "The app shows a digest bound to the network, the contract, the mission, the recipient and the amount."],
  confirm_payment: (s) => ["You", "You confirm this exact payment", `Digest ${s.send.digest.slice(0, 16)}… A different amount or recipient would not match.`],
  pay: (s) => ["Agent", "Pay", `A fake transaction, ${s.reply.tx}. No chain was involved.`],
  close: (s) => ["Agent", "Close the mission", `The journal is sealed: ${s.reply.entries} entries, head ${s.reply.head.slice(0, 16)}…`],
  exposure: (s) => ["Report", "Exposure report", `${s.reply.parties.length} parties received something. ${s.reply.model_calls_mock} of ${s.reply.model_calls} model calls were fakes, and ${s.reply.pseudonyms_replaced} term was replaced by a pseudonym.`],
};

// Which party a command reaches, so that its row lights up when the command runs.
function partyOf(s: Step): string | undefined {
  const find = (test: (p: Party) => boolean) => parties.find(test)?.party;
  switch (s.send.cmd) {
    case "search": return find((p) => p.kind === "search engine");
    case "read": return find((p) => p.party === `site ${s.send.handle}`);
    case "contact": return find((p) => p.kind === "contacted firm");
    case "pay": return find((p) => p.kind === "chain");
    default: return undefined;
  }
}

// The reply as text, with the label the program puts on its own fakes coloured.
function Reply({ value }: { value: Json }) {
  const pieces = JSON.stringify(value).split('"mode":"mock"');
  return (
    <>
      {pieces.map((piece, i) => (
        <span key={i}>
          {piece}
          {i < pieces.length - 1 ? <span className="mock">"mode":"mock"</span> : null}
        </span>
      ))}
    </>
  );
}

function Replay() {
  const [index, setIndex] = useState(0); // number of steps shown
  const [playing, setPlaying] = useState(false);
  const body = useRef<HTMLDivElement>(null);
  const done = index >= steps.length;

  useEffect(() => {
    if (!playing) return;
    if (done) {
      setPlaying(false);
      return;
    }
    const timer = window.setTimeout(() => setIndex((i) => i + 1), index === 0 ? 300 : 1700);
    return () => window.clearTimeout(timer);
  }, [playing, index, done]);

  useEffect(() => {
    if (body.current) body.current.scrollTop = body.current.scrollHeight;
  }, [index]);

  const shown = steps.slice(0, index);
  const last = shown[shown.length - 1];
  const [kind, title, note] = last
    ? (explain[last.send.cmd] ?? (() => ["", last.send.cmd, ""]))(last)
    : ["Ready", "Press play to run the mission.", `${steps.length} commands, from opening the mission to the exposure report.`];

  const reached = useMemo(() => {
    const set = new Set<string>();
    for (const s of shown) {
      const party = partyOf(s);
      if (party) set.add(party);
      if (s.send.cmd === "exposure") parties.forEach((p) => set.add(p.party));
    }
    return set;
  }, [index]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="player">
      <Reveal className="term">
        <div className="term-bar">
          <span className="title">{demo.source}</span>
          <span className="pill"><span className="dot" />every reply is a fake</span>
        </div>
        <div className="term-body" ref={body} tabIndex={0} aria-label="Recorded commands and replies" data-lenis-prevent>
          {shown.map((s, i) => (
            <motion.div key={i} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, ease: EASE }}>
              <div className="line send">{JSON.stringify(s.send)}</div>
              <div className="line reply"><Reply value={s.reply} /></div>
            </motion.div>
          ))}
        </div>
        <div className="controls">
          <button
            className="btn btn-primary btn-sm"
            type="button"
            onClick={() => {
              if (playing) return setPlaying(false);
              if (done) setIndex(0);
              setPlaying(true);
            }}
          >
            {playing ? "Pause" : done ? "Play again" : "Play"}
          </button>
          <button className="btn btn-ghost btn-sm" type="button" disabled={done} onClick={() => { setPlaying(false); setIndex((i) => Math.min(steps.length, i + 1)); }}>
            Next step
          </button>
          <button className="btn btn-ghost btn-sm" type="button" disabled={index === 0} onClick={() => { setPlaying(false); setIndex(0); }}>
            Restart
          </button>
          <span className="count"><NumberFlow locales="en-US" value={index} /> / {steps.length}</span>
        </div>
      </Reveal>

      <div className="side">
        <Reveal className="card" delay={0.08}>
          <span className="eyebrow">{kind}</span>
          <p className="stage" aria-live="polite">{title}</p>
          <p className="stage-note">{note}</p>
        </Reveal>
        <Reveal className="card" delay={0.16}>
          <h3>Who received what</h3>
          <p>Every party that received something during the mission, and how much. Rows light up as the mission reaches them.</p>
          <table className="exposure">
            <thead><tr><th>Party</th><th>Requests</th><th>Bytes sent to it</th></tr></thead>
            <tbody>
              {parties.map((p) => (
                <tr key={p.party} className={reached.has(p.party) ? "on" : undefined}>
                  <td>{p.party}</td><td>{p.requests}</td><td>{p.bytes_sent}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="note">
            {done
              ? `Recorded report: ${report.model_calls_real} real model calls, content readable by the relay: ${report.content_readable_by_relay}. Every party is labelled mock.`
              : "Counts come from the recorded report. The content itself is not shown, by design."}
          </p>
        </Reveal>
      </div>
    </div>
  );
}

// ---------- Pseudonym illustration ----------
// Simplified on purpose: whole words, case and accents ignored. Not ona-core's implementation.

// Lowercase and strip accents, one output character per input character, so offsets still line up.
function fold(chars: string[]): string[] {
  return chars.map((ch) => {
    const base = ch.normalize("NFKD").replace(/[̀-ͯ]/g, "").toLowerCase();
    return Array.from(base).length === 1 ? base : ch.toLowerCase();
  });
}
const isWord = (ch: string | undefined) => ch !== undefined && /[\p{L}\p{N}]/u.test(ch);

function randomPseudonym(): string {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => String.fromCharCode(65 + (b % 26))).join("");
}

type Piece = { text: string; masked: boolean };

function pseudonymize(input: string, declared: string, table: Map<string, string>): Piece[] {
  const chars = Array.from(input);
  const folded = fold(chars);
  const terms = declared.split(",").map((t) => fold(Array.from(t.trim()))).filter((t) => t.length > 0)
    .sort((a, b) => b.length - a.length);

  const pieces: Piece[] = [];
  let plain = "";
  let i = 0;
  while (i < chars.length) {
    const hit = terms.find((term) =>
      term.every((ch, k) => folded[i + k] === ch)
      && (!isWord(term[0]) || !isWord(folded[i - 1]))
      && (!isWord(term[term.length - 1]) || !isWord(folded[i + term.length])));
    if (!hit) {
      plain += chars[i];
      i += 1;
      continue;
    }
    if (plain) pieces.push({ text: plain, masked: false });
    plain = "";
    const key = hit.join("");
    if (!table.has(key)) table.set(key, randomPseudonym());
    pieces.push({ text: table.get(key)!, masked: true });
    i += hit.length;
  }
  if (plain) pieces.push({ text: plain, masked: false });
  return pieces;
}

function Playground() {
  const [terms, setTerms] = useState("Mr Dupont, Acme Logistics");
  const [text, setText] = useState("Mr Dupont was dismissed by Acme Logistics after twelve years. Which employment lawyers in Paris handle this, and what do they charge?");
  const table = useRef(new Map<string, string>()); // like the app's table: one pseudonym per term, kept while the page is open
  const pieces = pseudonymize(text, terms, table.current);

  return (
    <Reveal className="playground">
      <div>
        <div className="field">
          <label htmlFor="terms">Protected terms, separated by commas</label>
          <input id="terms" type="text" value={terms} onChange={(e) => setTerms(e.target.value)} autoComplete="off" spellCheck={false} />
        </div>
        <div className="field">
          <label htmlFor="text">Your request</label>
          <textarea id="text" rows={5} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} data-lenis-prevent />
        </div>
      </div>
      <div className="field">
        <label id="out-label">Text sent to the model</label>
        <div className="out" aria-labelledby="out-label" aria-live="polite">
          {pieces.length === 0 ? "Type a request on the left." : pieces.map((piece, i) => (piece.masked ? <mark key={i}>{piece.text}</mark> : <span key={i}>{piece.text}</span>))}
        </div>
        <p className="note after">
          A simplified copy that runs in your browser: whole words, any case, accents ignored. It is not the code of{" "}
          <code>ona-core</code>, whose rules and gaps are listed in the <a href={`${REPO}#what-pseudonyms-cover`}>README</a>.
          Nothing you type leaves this page.
        </p>
      </div>
    </Reveal>
  );
}

export function Demo() {
  return (
    <>
      <div className="page-head">
        <motion.div className="wrap" initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.8, ease: EASE }}>
          <span className="pill"><span className="dot" />mode: mock · recorded {demo.recorded}</span>
          <h1>A mission, replayed command by command.</h1>
          <p>
            Find a employment lawyer for Mr Dupont and compare fees, without the firms learning who he is. This is the recorded output of{" "}
            <code>ona demo</code>, the mission core running against a fake model, a fake web and fake payments. Nothing below touched a network.
          </p>
        </motion.div>
      </div>

      <section>
        <div className="wrap"><Replay /></div>
      </section>

      <section>
        <div className="wrap">
          <Reveal className="section-head">
            <span className="eyebrow">Try it · illustration</span>
            <h2>What the model would read.</h2>
            <p>Declare the terms to protect, then type. Each declared term becomes a random 12 letter pseudonym, and the reply is put back locally.</p>
          </Reveal>
          <Playground />
        </div>
      </section>

      <section>
        <div className="wrap">
          <Reveal className="section-head">
            <span className="eyebrow">Video</span>
            <h2>The apps on screen.</h2>
          </Reveal>
          <Reveal className="video-slot">
            <div>
              <p><strong>No video published yet.</strong></p>
              <p className="note">A recording of the desktop app and the iPhone remote will be placed here.</p>
            </div>
          </Reveal>
        </div>
      </section>
    </>
  );
}
