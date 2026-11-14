import { Link, useParams } from "react-router-dom";
import { motion } from "motion/react";
import { EASE, REPO } from "../components/Layout";
import { Reveal } from "../components/Reveal";
import { ScannerBackdrop } from "../components/ScannerBackdrop";

// No packaged build exists yet. When one does, give its entry a `download` URL (with its size, date and SHA-256 in
// `notes`) and the page shows a real download button. Build commands come from docs/INSTALL.md and docs/*/app.md.
// `/downloads/<id>` shows one platform only (that is where the install cards of the home page lead);
// `/downloads` lists them all.
type Platform = {
  id: string; name: string; kind: string; download?: string; state: string;
  build: string; needs: string[]; notes: string[]; source: string;
};

const TAURI_BUILD = "cd desktop/tauri/src-tauri\ncargo run --locked";

export const platforms: Platform[] = [
  {
    id: "mac", name: "Mac", kind: "Desktop app · SwiftUI", state: "Build from source",
    build: "desktop/OnaCoreBridge/build.sh\nopen desktop/ONADesktop/ONADesktop.xcodeproj",
    needs: ["macOS on Apple Silicon, with Xcode", "Rust 1.99.1", "tor from Homebrew, for the phone to reach the app"],
    notes: ["Signed to run locally only.", "Conversations and confirmations work against a fake model, web and payments. No wallet yet."],
    source: `${REPO}/tree/main/desktop/ONADesktop`,
  },
  {
    id: "windows", name: "Windows", kind: "Desktop app · Tauri", state: "Build from source, untested there", build: TAURI_BUILD,
    needs: ["Rust 1.99.1", "WebView2 (already on an up to date Windows 10 or 11)", "The MSVC build tools", "The Tor Expert Bundle, with tor.exe in the PATH"],
    notes: ["Never built or run on Windows: so far the Tauri app has only run on macOS.", "An installer (.msi) has never been produced."],
    source: `${REPO}/tree/main/desktop/tauri`,
  },
  {
    id: "linux", name: "Linux", kind: "Desktop app · Tauri", state: "Build from source, untested there", build: TAURI_BUILD,
    needs: ["Rust 1.99.1", "WebKitGTK 4.1, GTK 3, librsvg and libayatana-appindicator (development packages)", "The tor package"],
    notes: ["Never built or run on Linux: so far the Tauri app has only run on macOS.", "Packages (.deb, .rpm, AppImage) have never been produced."],
    source: `${REPO}/tree/main/desktop/tauri`,
  },
  {
    id: "iphone", name: "iPhone", kind: "Mobile app · Swift", state: "Build from source",
    build: "ios/ArtiBridge/build-xcframework.sh\nopen ios/ONA/ONA.xcodeproj",
    needs: ["A Mac with Xcode", "Rust 1.99.1", "About 5 minutes for the first build of the Tor library", "A desktop app running on your computer to pair with"],
    notes: ["A remote control: it follows a mission and confirms actions, and holds no tokens.", "Tested in the iOS simulator. The Secure Enclave key path has not run on a device yet.", "The first connections over Tor often took more than 60 s."],
    source: `${REPO}/tree/main/ios`,
  },
];

function Card({ p, large }: { p: Platform; large?: boolean }) {
  return (
    <article className={large ? "card dl dl-one" : "card dl"}>
      <span className="eyebrow">{p.kind}</span>
      <h3>{p.name}</h3>
      <span className="pill"><span className="dot" />{p.state}</span>
      <pre data-lenis-prevent><code>{`git clone ${REPO}.git && cd ona\n${p.build}`}</code></pre>
      <ul>
        {p.needs.map((need) => <li key={need}>{need}</li>)}
      </ul>
      {p.notes.map((note) => <p className="note" key={note}>{note}</p>)}
      <div className="dl-actions">
        {p.download
          ? <a className="btn btn-primary btn-sm" href={p.download}>Download for {p.name}</a>
          : <span className="btn btn-ghost btn-sm" aria-disabled="true">Installer not available yet</span>}
        <a className="btn btn-ghost btn-sm" href={p.source}>Source code</a>
        {large ? null : <Link className="btn btn-ghost btn-sm" to={`/downloads/${p.id}`}>Only {p.name}</Link>}
      </div>
    </article>
  );
}

export function Downloads() {
  const { platform } = useParams();
  const one = platforms.find((p) => p.id === platform);

  return (
    <>
      <ScannerBackdrop page />
      <div className="page-head">
        <motion.div className="wrap" key={one?.id ?? "all"} initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.8, ease: EASE }}>
          <span className="pill"><span className="dot" />No packaged build yet</span>
          <h1>{one ? `Install ONA on ${one.name}.` : "Install ONA."}</h1>
          <p>
            ONA is an early prototype: there is no installer to download today, and we will not link a file we have not built and
            checked. {one ? "This app" : "Each app"} can be built from the source code. Everything runs against fakes, so do not
            use real funds.
          </p>
          <nav className="dl-switch" aria-label="Platform">
            {platforms.map((p) => (
              <Link key={p.id} className={p.id === one?.id ? "on" : undefined} to={`/downloads/${p.id}`}>{p.name}</Link>
            ))}
            <Link className={one ? undefined : "on"} to="/downloads">All</Link>
          </nav>
        </motion.div>
      </div>

      <section>
        <div className="wrap">
          {one ? (
            <Reveal key={one.id}><Card p={one} large /></Reveal>
          ) : (
            <div className="grid-2">
              {platforms.map((p, i) => <Reveal key={p.id} delay={i * 0.06}><Card p={p} /></Reveal>)}
            </div>
          )}
          {platform && !one ? <p className="note after">No such platform: showing them all.</p> : null}
        </div>
      </section>
    </>
  );
}
