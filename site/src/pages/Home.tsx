import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { REPO, lockScroll } from "../components/Layout";
import { Reveal } from "../components/Reveal";
import { Fall } from "../components/Fall";
import DecryptedText from "../components/reactbits/DecryptedText";
import { InstallDeck } from "../components/InstallDeck";
import { Metrics } from "../components/Metrics";
import demo from "../data/demo.json";

// The home page says three things, in this order: what the agent does (the slides of the fall), how to get it
// (the install cards), and why it can be trusted (the measured data, then what is not ready). The rest is in the README.

const report = demo.steps[demo.steps.length - 1].reply as { model_calls: number; model_calls_mock: number };

const notReady = [
  "The model, the web and the payments in the app are still fakes, and nothing is deployed on testnet.",
  "The relay in front of the model can read the request until the client verifies the enclave's quotes.",
  "Nothing has been audited. Do not use real funds.",
];

// The opening plays once per visit of the site; coming back to the home page lands directly.
let seen = false;

export function Home() {
  const [run, setRun] = useState(0); // "Replay the fall" starts a new run
  const [skip] = useState(() => seen || window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  const [landed, setLanded] = useState(skip);
  const [shown, setShown] = useState(skip); // the landing text appears when "Enter" is pressed
  const show = useCallback(() => setShown(true), []);
  const land = useCallback(() => {
    seen = true;
    setLanded(true);
  }, []);

  useEffect(() => {
    lockScroll(!landed);
    return () => lockScroll(false);
  }, [landed]);

  return (
    <div className="home">
      <Fall key={run} skip={run === 0 && skip} onReformed={show} onLanded={land} />

      <div className={shown ? "landing" : "landing waiting"} inert={!landed}>
        <section className="landing-hero">
          <div className="wrap">
            <span className="pill"><span className="dot" />Early prototype · not audited · no real funds</span>
            <h1>
              {/* remounted when the page appears, so that the first decryption is seen; then it loops */}
              <DecryptedText key={String(shown)} text="Ask what you want." animateOn="inViewHover" sequential revealDirection="start" speed={60} loop loopDelay={2600} encryptedClassName="noise" />
            </h1>
            <p className="lead">
              ONA is a private AI agent with a wallet on NEAR. It answers, pays, places and withdraws for you, and asks before
              each action. Pick your machine to install it, and your phone to follow along.
            </p>
          </div>

          <InstallDeck shown={shown} />

          <div className="wrap">
            <div className="cta">
              <Link className="btn btn-primary" to="/demo">Watch a mission run</Link>
              <a className="btn btn-ghost" href={REPO}>Read the code</a>
              <button className="btn btn-ghost" type="button" onClick={() => { window.scrollTo(0, 0); setLanded(false); setShown(false); setRun((r) => r + 1); }}>
                Replay the fall
              </button>
            </div>
          </div>
        </section>

        <Metrics mockCalls={report.model_calls_mock} modelCalls={report.model_calls} recorded={demo.recorded} />

        <section id="limits">
          <div className="wrap">
            <Reveal className="section-head">
              <span className="eyebrow">Not ready yet</span>
              <h2>What a prototype means here.</h2>
            </Reveal>
            <Reveal tag="ul" className="limits">
              {notReady.map((line) => <li key={line}>{line}</li>)}
            </Reveal>
            <Reveal tag="p" className="note after">
              The complete list of limitations, and what each part was tested on, is in the <a href={`${REPO}#known-limitations`}>README</a>.
            </Reveal>
          </div>
        </section>
      </div>
    </div>
  );
}
