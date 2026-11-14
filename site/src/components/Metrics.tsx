import { useRef, useState } from "react";
import { motion, useInView } from "motion/react";
import NumberFlow from "@number-flow/react";
import { EASE, REPO } from "./Layout";
import { Reveal } from "./Reveal";
import { ScannerBackdrop } from "./ScannerBackdrop";

// The measurements, laid out as a board: one line per figure, with where it comes from, when, and what kind of
// figure it is. The layout borrows from the departure board of departuremono.com and the ruled grid of voidzero.dev.
//
// Every figure has a source in the repository. Change a figure only together with its source and date.
//  - anonymity set: README, "Known limitations"
//  - gas: SPEC.md, "Measured gas" (near-sandbox 2.13.4, 2026-11-10)
//  - model calls: src/data/demo.json, the recorded exposure report
//  - crowd simulation: crates/ona-crowd/PARADES.md (simulated only, 2026-11-11), columns "Observer finds" and "Blind"

type Row = {
  code: string; what: string; value: number; digits?: number; unit: string;
  where: string; when: string; state: "Stated" | "Measured" | "Recorded" | "Simulated";
  detail: string[]; source: string; href: string;
};

export function Metrics({ mockCalls, modelCalls, recorded }: { mockCalls: number; modelCalls: number; recorded: string }) {
  const rows: Row[] = [
    {
      code: "ANS", what: "Anonymity set at launch", value: 1, unit: "user", where: "README", when: "—", state: "Stated",
      detail: ["With one user there is nobody to hide among.", "ONA claims no unlinkability until a measured number of users is published."],
      source: "README.md · Known limitations", href: `${REPO}#known-limitations`,
    },
    {
      code: "SPD", what: "One blind payment to a third party", value: 13.4, digits: 1, unit: "Tgas", where: "Local node", when: "2026-11-10", state: "Measured",
      detail: ["Gas burnt by a spend with no change on the mint contract, receipts included.", "near-sandbox 2.13.4.", "Measured before the contract changes of 2026-11-11 and not measured again."],
      source: "SPEC.md · Measured gas", href: `${REPO}/blob/main/SPEC.md#measured-gas`,
    },
    {
      code: "RDM", what: "One redemption of a token", value: 19.0, digits: 1, unit: "Tgas", where: "Local node", when: "2026-11-10", state: "Measured",
      detail: ["Gas burnt by a redeem on the mint contract, receipts included.", "near-sandbox 2.13.4.", "Measured before the contract changes of 2026-11-11 and not measured again."],
      source: "SPEC.md · Measured gas", href: `${REPO}/blob/main/SPEC.md#measured-gas`,
    },
    {
      code: "MCK", what: "Model calls answered by a fake", value: mockCalls, unit: `of ${modelCalls}`, where: "Recorded demo", when: recorded, state: "Recorded",
      detail: ["In the mission on the demo page, every model call, web page and payment is a fake.", "The program labels them itself: mode: mock."],
      source: "ona demo · exposure report", href: "/demo",
    },
    {
      code: "OBS", what: "Observer finds a user's vault", value: 93, unit: "%", where: "Crowd simulation", when: "2026-11-11", state: "Simulated",
      detail: ["No countermeasure. 50 users, every deposit the same size, 2 vaults, 6 simulated hours, seeds 1 to 10.", "Nothing here has run on a chain."],
      source: "ona-crowd · PARADES.md", href: `${REPO}/blob/main/crates/ona-crowd/PARADES.md`,
    },
    {
      code: "SEP", what: "The same, with separate accounting", value: 61, unit: "%", where: "Crowd simulation", when: "2026-11-11", state: "Simulated",
      detail: ["A 20 % reserve, net settlement every 1,800 s, at least 10 active requests per settlement.", "Same 50 users. The figures err on the side of less privacy."],
      source: "ona-crowd · PARADES.md", href: `${REPO}/blob/main/crates/ona-crowd/PARADES.md`,
    },
    {
      code: "BLD", what: "A blind guess, for comparison", value: 56, unit: "%", where: "Crowd simulation", when: "2026-11-11", state: "Simulated",
      detail: ["The share of the most chosen vault: what an observer gets by always naming it.", "This is the floor the two lines above are compared to."],
      source: "ona-crowd · PARADES.md", href: `${REPO}/blob/main/crates/ona-crowd/PARADES.md`,
    },
  ];
  const [picked, setPicked] = useState(1);
  const board = useRef<HTMLDivElement>(null);
  const inView = useInView(board, { once: true, amount: 0.25 });
  const row = rows[picked];

  return (
    <section id="metrics" className="scanned">
      <ScannerBackdrop />
      <div className="wrap">
        <Reveal className="section-head">
          <span className="eyebrow">Safety, measured</span>
          <h2>Why you can trust it: the numbers, dated.</h2>
          <p>ONA is built so that no single party gets both who you are and what you asked. This is what has been measured so far. Each line says where it comes from and whether it was measured, recorded or only simulated.</p>
        </Reveal>

        <Reveal className="board">
          <div className="board-main" ref={board}>
            <div className="board-row board-head" aria-hidden="true">
              <span>Code</span><span>Measure</span><span>Value</span><span>Where</span><span>When</span><span>Kind</span>
            </div>
            {rows.map((r, i) => (
              <button
                type="button"
                key={r.code}
                className={i === picked ? "board-row on" : "board-row"}
                aria-pressed={i === picked}
                onMouseEnter={() => setPicked(i)}
                onFocus={() => setPicked(i)}
                onClick={() => setPicked(i)}
              >
                <span className="code">{r.code}</span>
                <span className="what">{r.what}</span>
                <span className="value">
                  <NumberFlow locales="en-US" value={inView ? r.value : 0} format={{ minimumFractionDigits: r.digits ?? 0, maximumFractionDigits: r.digits ?? 0 }} />
                  <small>{r.unit}</small>
                </span>
                <span className="where">{r.where}</span>
                <span className="when">{r.when}</span>
                <span className={`kind kind-${r.state.toLowerCase()}`}>{r.state}</span>
              </button>
            ))}
          </div>

          <aside className="board-side" aria-live="polite">
            <div className="board-term">
              <div className="board-term-bar"><span>{row.code}</span><span>{row.state.toLowerCase()}</span></div>
              <motion.div key={row.code} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, ease: EASE }}>
                <p className="board-term-title">{row.what}</p>
                {row.detail.map((line) => <p key={line} className="board-term-line">{line}</p>)}
                <p className="board-term-src">
                  source <a href={row.href}>{row.source}</a>
                </p>
              </motion.div>
            </div>
          </aside>
        </Reveal>

        <Reveal tag="p" className="note after">
          The simulation covers more cases (500 users, varied deposits) and they are less flattering: the full tables and the
          method are in <a href={`${REPO}/blob/main/crates/ona-crowd/PARADES.md`}>PARADES.md</a>.
        </Reveal>
      </div>
    </section>
  );
}
