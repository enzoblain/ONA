import { useEffect, useRef, useState } from "react";
import { createWorld, SLIDES, type World } from "../three/world";

// intro → starting → falling → landing → arrived (in the cave, "Enter" is offered) → entering → landed (the pages)
type Phase = "intro" | "starting" | "falling" | "landing" | "arrived" | "entering" | "landed";

// The opening of the home page: the 3D world (three/world.ts) with the slides and the controls on top of it.
// The slides are driven the way the 4ward home page is: the wheel, a swipe or the keyboard add to a progress
// value (going back up takes it back), with no native scroll. The ghost lands in a cave; "Enter" leads to the
// pages, and the same canvas stays behind the top of the landing page.

const WHEEL_DISTANCE = 900; // wheel pixels for one slide
const SWIPE_DISTANCE = 260; // finger pixels for one slide

type Slide = { eyebrow: string; title: string; text?: string; items?: [string, string][]; note?: string };

// What the agent does, one slide per verb. The slides describe the product as designed (README, "What it is" and
// "Planned architecture"), not what runs today: where each part stands is said on the landing page, under the data.
const slides: Slide[] = [
  {
    eyebrow: "Ask",
    title: "Ask it anything you would rather not sign.",
    text: "Legal, medical, financial or professional. The agent searches the web, reads, compares and contacts a professional for you.",
    note: "The names you declare leave your computer as pseudonyms.",
  },
  {
    eyebrow: "Pay",
    title: "Let it pay or transfer, once you say yes.",
    items: [
      ["You confirm", "the recipient and the amount, every time"],
      ["It pays", "with blind tokens: the mint that holds your deposit cannot link it to the payment"],
      ["Change", "comes back to you blinded"],
    ],
    note: "Your wallet signs once, for the deposit. After that, tokens do the talking.",
  },
  {
    eyebrow: "Place",
    title: "Put your money to work in a vault.",
    items: [
      ["Deposit", "from your own wallet into the pool, where it becomes blind cash notes"],
      ["Enter", "a listed staking vault: the agent places for you"],
      ["Switch", "to another vault whenever you want, and follow your portfolio"],
    ],
    note: "The pool has no access key, and only places in listed vaults.",
  },
  {
    eyebrow: "Withdraw",
    title: "Take it back out, to your own account.",
    items: [
      ["Exit", "to cash, then to the account that deposited, and only to it"],
      ["Unnamed", "the payout does not say which vault you chose"],
      ["Escape", "after 7 days you can get out without the agent"],
    ],
    note: "Keep falling to land.",
  },
];

export function Fall({ skip, onReformed, onLanded }: { skip: boolean; onReformed: () => void; onLanded: () => void }) {
  const root = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const world = useRef<World | null>(null);
  const [phase, setPhase] = useState<Phase>(skip ? "landed" : "intro");
  const live = useRef({ p: 0, q: 0 }); // p: where the input wants to be; q follows it smoothly
  const done = useRef({ onReformed, onLanded });
  done.current = { onReformed, onLanded };

  useEffect(() => {
    const w = createWorld(canvas.current!, { reduced: window.matchMedia("(prefers-reduced-motion: reduce)").matches });
    world.current = w;
    if (skip) w.landed();
    return () => { w.dispose(); world.current = null; };
  }, [skip]);

  const land = () => {
    setPhase("landing");
    world.current?.land(() => setPhase("arrived"));
  };
  const enter = () => {
    setPhase("entering");
    done.current.onReformed(); // the landing page starts to appear while the camera rises
    world.current?.enter(() => { setPhase("landed"); done.current.onLanded(); });
  };
  const landRef = useRef(land);
  landRef.current = land;

  // While falling: follow the progress, hand it to the world, place the slides.
  useEffect(() => {
    if (phase !== "falling") return;
    const s = live.current;
    const slideEls = Array.from(root.current!.querySelectorAll<HTMLElement>(".slide"));
    const dots = Array.from(root.current!.querySelectorAll<HTMLElement>(".fall-dots span"));
    let raf = 0, last = performance.now();
    const frame = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      const before = s.q;
      s.q += (s.p - s.q) * Math.min(1, dt * 4.2);
      const state = world.current?.state;
      if (state) { state.q = s.q; state.qSpeed = Math.abs(s.q - before) / Math.max(dt, 0.001); }
      slideEls.forEach((slide, i) => {
        const d = i + 0.5 - s.q;
        // A slide comes up from below, rests while the camera rests, and leaves upwards.
        const rest = Math.sign(d) * Math.max(0, Math.abs(d) - 0.2);
        slide.style.transform = `translate3d(0, calc(-50% + ${(rest * 90).toFixed(2)}vh), 0)`;
        slide.style.opacity = String(Math.max(0, 1 - Math.max(0, Math.abs(d) - 0.2) * 3.4).toFixed(3));
      });
      const current = Math.max(0, Math.min(SLIDES - 1, Math.floor(s.q)));
      dots.forEach((dot, i) => dot.classList.toggle("on", i === current));
      if (s.p >= SLIDES && s.q > SLIDES - 0.05) { landRef.current(); return; }
      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);

    let touchY: number | null = null;
    const push = (delta: number) => { s.p = Math.min(SLIDES, Math.max(0, s.p + delta)); };
    const onWheel = (e: WheelEvent) => { e.preventDefault(); push(e.deltaY / WHEEL_DISTANCE); };
    const onTouchStart = (e: TouchEvent) => { touchY = e.touches[0].clientY; };
    const onTouchMove = (e: TouchEvent) => {
      if (touchY === null) return;
      e.preventDefault();
      const y = e.touches[0].clientY;
      push((touchY - y) / SWIPE_DISTANCE); // finger up = further down
      touchY = y;
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof Element && e.target.closest("a, button") && (e.key === " " || e.key === "Enter")) return;
      if (["ArrowDown", "PageDown", " ", "Enter"].includes(e.key)) { e.preventDefault(); push(0.5); }
      if (["ArrowUp", "PageUp"].includes(e.key)) { e.preventDefault(); push(-0.5); }
    };
    window.addEventListener("wheel", onWheel, { passive: false });
    window.addEventListener("touchstart", onTouchStart, { passive: true });
    window.addEventListener("touchmove", onTouchMove, { passive: false });
    window.addEventListener("keydown", onKey);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("wheel", onWheel);
      window.removeEventListener("touchstart", onTouchStart);
      window.removeEventListener("touchmove", onTouchMove);
      window.removeEventListener("keydown", onKey);
    };
  }, [phase]);

  const start = () => {
    setPhase("starting");
    world.current?.start(() => {
      live.current.p = 0.5; // the first slide arrives by itself
      setPhase("falling");
    });
  };
  const skipAll = () => {
    world.current?.landed();
    setPhase("landed");
    done.current.onReformed();
    done.current.onLanded();
  };

  return (
    <div className={`fall is-${phase}`} ref={root}>
      <canvas className="fall-canvas" ref={canvas} aria-hidden="true" />

      {phase === "landed" ? null : (
        <>
          <div className="fall-slides">
            {slides.map((slide, i) => (
              <article className={i % 2 === 0 ? "slide right" : "slide left"} key={slide.eyebrow} aria-hidden={phase !== "falling"}>
                <span className="eyebrow">{String(i + 1).padStart(2, "0")} · {slide.eyebrow}</span>
                <h2>{slide.title}</h2>
                {slide.text ? <p>{slide.text}</p> : null}
                {slide.items ? (
                  <dl>
                    {slide.items.map(([term, detail]) => (
                      <div key={term}><dt>{term}</dt><dd>{detail}</dd></div>
                    ))}
                  </dl>
                ) : null}
                {slide.note ? <p className="note">{slide.note}</p> : null}
              </article>
            ))}
          </div>

          <div className="fall-intro">
            <button className="btn btn-primary" type="button" disabled={phase !== "intro"} onClick={start}>Start</button>
            <button className="fall-skip" type="button" disabled={phase !== "intro"} onClick={skipAll}>Skip the intro</button>
          </div>

          <div className="fall-enter">
            <button className="btn btn-primary" type="button" disabled={phase !== "arrived"} onClick={enter}>Enter</button>
          </div>

          <div className="fall-hud" aria-hidden={phase !== "falling"}>
            <div className="fall-dots">{slides.map((slide) => <span key={slide.eyebrow} />)}</div>
            <p className="fall-hint">Scroll to keep falling ↓</p>
            <button className="fall-skip" type="button" tabIndex={phase === "falling" ? 0 : -1} onClick={() => { live.current.p = SLIDES; live.current.q = SLIDES; land(); }}>
              Skip to the landing
            </button>
          </div>
        </>
      )}
    </div>
  );
}
