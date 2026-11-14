import { useEffect } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { motion } from "motion/react";
import Lenis from "lenis";
import gsap from "gsap";

export const REPO = "https://github.com/enzoblain/ona";
export const EASE = [0.22, 1, 0.36, 1] as const;

let lenis: Lenis | null = null;
let locked = false;

// Stops the page from scrolling (the opening of the home page drives its own slides).
export function lockScroll(lock: boolean) {
  locked = lock;
  document.documentElement.classList.toggle("scroll-locked", lock);
  if (lock) lenis?.stop();
  else lenis?.start();
}

// Smooth scroll (Lenis), driven by GSAP's ticker: one clock for every animation.
function useSmoothScroll() {
  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const instance = new Lenis({ autoRaf: false });
    lenis = instance;
    if (locked) instance.stop();
    const tick = (time: number) => instance.raf(time * 1000);
    gsap.ticker.add(tick);
    gsap.ticker.lagSmoothing(0);
    return () => {
      gsap.ticker.remove(tick);
      instance.destroy();
      lenis = null;
    };
  }, []);
}

const titles: Record<string, string> = {
  "/": "ONA: a private AI assistant",
  "/demo": "Demo · ONA",
  "/downloads": "Install · ONA",
};

export function Layout() {
  useSmoothScroll();
  const { pathname } = useLocation();

  useEffect(() => {
    document.title = titles[pathname] ?? (pathname.startsWith("/downloads/") ? "Install · ONA" : "Page not found · ONA");
    if (lenis) lenis.scrollTo(0, { immediate: true, force: true });
    window.scrollTo(0, 0);
  }, [pathname]);

  return (
    <>
      <a className="skip" href="#main">Skip to content</a>

      {/* No banner: a quiet wordmark on the left, a quiet link on the right. */}
      <motion.header className="top" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 1.2, ease: EASE, delay: 0.3 }}>
        <NavLink className="top-brand" to="/">ONA</NavLink>
        <nav aria-label="Main">
          <NavLink className="top-link" to="/demo">Demo</NavLink>
          <NavLink className="top-link" to="/downloads">Install</NavLink>
        </nav>
      </motion.header>

      <main id="main">
        <Outlet />
      </main>

      <footer>
        <div className="wrap row">
          <span>
            ONA · MIT licence · © 2026 Hugo Thomas &amp; Enzo Blain · This site sets no cookie and loads nothing from a third party.
          </span>
          <nav aria-label="Footer">
            <NavLink to="/demo">Demo</NavLink>
            <NavLink to="/downloads">Downloads</NavLink>
            <a href={REPO}>GitHub</a>
            <a href={`${REPO}/blob/main/SPEC.md`}>Spec</a>
          </nav>
        </div>
      </footer>
    </>
  );
}
