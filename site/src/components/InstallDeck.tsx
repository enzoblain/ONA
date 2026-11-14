import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { animate, motion, useMotionValue } from "motion/react";

// The four ways in, as large glass cards that are browsed sideways: drag, swipe, arrow keys, the arrows or the dots.
// Each card leads to the page of its own platform, with the installers of the latest release.
const installs = [
  { id: "mac", name: "Mac", kind: "Desktop app", state: "Signed and notarized", note: "The SwiftUI app, for Apple silicon." },
  { id: "windows", name: "Windows", kind: "Desktop app", state: "Installer, not run on a real PC yet", note: "The Tauri app, as an .exe or an .msi." },
  { id: "linux", name: "Linux", kind: "Desktop app", state: "Packages, not run on a real machine yet", note: "The Tauri app, as an AppImage, a .deb or an .rpm." },
  { id: "iphone", name: "iPhone", kind: "Mobile app", state: "TestFlight, not public yet", note: "A remote control for your computer, over Tor." },
];

const SPRING = { type: "spring", stiffness: 210, damping: 28 } as const;

export function InstallDeck({ shown }: { shown: boolean }) {
  const [index, setIndex] = useState(0);
  const [step, setStep] = useState(0); // distance between two cards
  const track = useRef<HTMLDivElement>(null);
  const x = useMotionValue(0);
  const dragged = useRef(false);
  const wheel = useRef({ sum: 0, until: 0 });

  useEffect(() => {
    const measure = () => {
      const cards = track.current?.children;
      if (cards && cards.length > 1) setStep((cards[1] as HTMLElement).offsetLeft - (cards[0] as HTMLElement).offsetLeft);
    };
    measure();
    window.addEventListener("resize", measure);
    return () => window.removeEventListener("resize", measure);
  }, []);

  const go = (next: number) => {
    const clamped = Math.max(0, Math.min(installs.length - 1, next));
    setIndex(clamped);
    animate(x, -clamped * step, SPRING);
  };
  useEffect(() => { x.set(-index * step); }, [step]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <motion.div
      className="deck"
      role="group"
      aria-roledescription="carousel"
      aria-label="Install ONA"
      tabIndex={0}
      initial={false}
      animate={shown ? { opacity: 1, y: 0 } : { opacity: 0, y: 32 }}
      transition={{ duration: 0.9, ease: [0.22, 1, 0.36, 1], delay: shown ? 0.35 : 0 }}
      onKeyDown={(e) => {
        if (e.key === "ArrowRight") { e.preventDefault(); go(index + 1); }
        if (e.key === "ArrowLeft") { e.preventDefault(); go(index - 1); }
      }}
      onWheel={(e) => {
        // a sideways swipe on a trackpad moves one card at a time
        if (Math.abs(e.deltaX) <= Math.abs(e.deltaY)) return;
        const now = performance.now(), w = wheel.current;
        if (now < w.until) return;
        w.sum += e.deltaX;
        if (Math.abs(w.sum) > 60) { go(index + Math.sign(w.sum)); w.sum = 0; w.until = now + 450; }
      }}
    >
      <motion.div
        className="deck-track"
        ref={track}
        style={{ x }}
        drag="x"
        dragConstraints={{ left: -(installs.length - 1) * step, right: 0 }}
        dragElastic={0.14}
        onDragStart={() => { dragged.current = true; }}
        onDragEnd={(_, info) => {
          const moved = info.offset.x + info.velocity.x * 0.18;
          go(index - Math.round(moved / (step || 1)));
          window.setTimeout(() => { dragged.current = false; }, 60);
        }}
      >
        {installs.map((item, i) => (
          <motion.article
            key={item.name}
            className={i === index ? "glass on" : "glass"}
            aria-hidden={i !== index}
            animate={{ scale: i === index ? 1 : 0.86, opacity: i === index ? 1 : 0.42 }}
            transition={SPRING}
            onClick={() => { if (!dragged.current && i !== index) go(i); }}
            onPointerMove={(e) => {
              // the highlight on the glass follows the pointer
              const box = e.currentTarget.getBoundingClientRect();
              e.currentTarget.style.setProperty("--mx", `${((e.clientX - box.left) / box.width) * 100}%`);
              e.currentTarget.style.setProperty("--my", `${((e.clientY - box.top) / box.height) * 100}%`);
            }}
          >
            <span className="glass-kind">{item.kind}</span>
            <h2>{item.name}</h2>
            <p>{item.note}</p>
            <div className="glass-foot">
              <span className="pill"><span className="dot" />{item.state}</span>
              <Link
                className="glass-go"
                to={`/downloads/${item.id}`}
                tabIndex={i === index ? 0 : -1}
                draggable={false}
                onClick={(e) => { if (dragged.current || i !== index) e.preventDefault(); }}
              >
                Install on {item.name} <span aria-hidden="true">→</span>
              </Link>
            </div>
          </motion.article>
        ))}
      </motion.div>

      <div className="deck-nav">
        <button type="button" aria-label="Previous" disabled={index === 0} onClick={() => go(index - 1)}>←</button>
        <div className="deck-dots">
          {installs.map((item, i) => (
            <button type="button" key={item.name} className={i === index ? "on" : undefined} aria-label={item.name} aria-current={i === index} onClick={() => go(i)} />
          ))}
        </div>
        <button type="button" aria-label="Next" disabled={index === installs.length - 1} onClick={() => go(index + 1)}>→</button>
      </div>
    </motion.div>
  );
}
