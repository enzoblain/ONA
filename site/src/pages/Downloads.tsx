import { Link, useParams } from "react-router-dom";
import { motion } from "motion/react";
import { EASE, REPO } from "../components/Layout";
import { Reveal } from "../components/Reveal";
import { ScannerBackdrop } from "../components/ScannerBackdrop";

// Installers come from the GitHub release v0.1.1 (published 2026-11-12, built by .github/workflows/release.yml:
// see docs/RELEASE.md). When a new version is published, update RELEASE and the file names below.
// `/downloads/<id>` shows one platform only (that is where the install cards of the home page lead);
// `/downloads` lists them all.
const RELEASE = "v0.1.1";
const file = (name: string) => `${REPO}/releases/download/${RELEASE}/${name}`;

type Platform = {
  id: string; name: string; kind: string; state: string;
  downloads: { label: string; href: string }[];
  build: string; needs: string[]; notes: string[]; source: string;
};

const TAURI_BUILD = "cd desktop/tauri/src-tauri\ncargo run --locked";

export const platforms: Platform[] = [
  {
    id: "mac", name: "Mac", kind: "Desktop app · SwiftUI", state: `Download · ${RELEASE}`,
    downloads: [{ label: "Download for Mac (.zip)", href: file("ONA-macOS-arm64.zip") }],
    build: "desktop/OnaCoreBridge/build.sh\nopen desktop/ONADesktop/ONADesktop.xcodeproj",
    needs: ["A Mac with Apple silicon", "tor from Homebrew, for the Tor mode and for the phone to reach the app"],
    notes: ["The release build is signed and notarized.", "The model, the web and the payments are still simulated in the app (mode: mock)."],
    source: `${REPO}/tree/main/desktop/ONADesktop`,
  },
  {
    id: "windows", name: "Windows", kind: "Desktop app · Tauri", state: `Download · ${RELEASE}`,
    downloads: [
      { label: "Download for Windows (.exe)", href: file("ONA_0.1.0_x64-setup.exe") },
      { label: ".msi", href: file("ONA_0.1.0_x64_en-US.msi") },
    ],
    build: TAURI_BUILD,
    needs: ["Windows 10 or 11, 64-bit, with WebView2", "The Tor Expert Bundle, with tor.exe in the PATH, for the Tor mode"],
    notes: ["Built on GitHub's machines. The app has not been run on a real Windows machine yet.", "The model, the web and the payments are still simulated in the app (mode: mock)."],
    source: `${REPO}/tree/main/desktop/tauri`,
  },
  {
    id: "linux", name: "Linux", kind: "Desktop app · Tauri", state: `Download · ${RELEASE}`,
    downloads: [
      { label: "Download for Linux (.AppImage)", href: file("ONA_0.1.0_amd64.AppImage") },
      { label: ".deb", href: file("ONA_0.1.0_amd64.deb") },
      { label: ".rpm", href: file("ONA-0.1.0-1.x86_64.rpm") },
    ],
    build: TAURI_BUILD,
    needs: ["A 64-bit x86 Linux", "The tor package, for the Tor mode"],
    notes: ["Built on GitHub's machines. The app has not been run on a real Linux machine yet.", "The model, the web and the payments are still simulated in the app (mode: mock)."],
    source: `${REPO}/tree/main/desktop/tauri`,
  },
  {
    id: "iphone", name: "iPhone", kind: "Mobile app · Swift", state: "TestFlight, not public yet",
    downloads: [],
    build: "ios/ArtiBridge/build-xcframework.sh\nopen ios/ONA/ONA.xcodeproj",
    needs: ["A desktop app running on your computer to pair with", "To build it yourself: a Mac with Xcode and Rust 1.99.1"],
    notes: ["A TestFlight build exists, but it is not open to the public yet.", "A remote control: it follows a mission and confirms actions, and holds no tokens.", "Not run on a real iPhone yet: tested in the iOS simulator."],
    source: `${REPO}/tree/main/ios`,
  },
];

function Card({ p, large }: { p: Platform; large?: boolean }) {
  return (
    <article className={large ? "card dl dl-one" : "card dl"}>
      <span className="eyebrow">{p.kind}</span>
      <h3>{p.name}</h3>
      <span className="pill"><span className="dot" />{p.state}</span>
      <div className="dl-actions">
        {p.downloads.length === 0 ? <span className="btn btn-ghost btn-sm" aria-disabled="true">No public download yet</span> : null}
        {p.downloads.map((d, i) => (
          <a key={d.href} className={i === 0 ? "btn btn-primary btn-sm" : "btn btn-ghost btn-sm"} href={d.href}>{d.label}</a>
        ))}
      </div>
      <ul>
        {p.needs.map((need) => <li key={need}>{need}</li>)}
      </ul>
      {p.notes.map((note) => <p className="note" key={note}>{note}</p>)}
      <p className="dl-sub">Or build it from the source code:</p>
      <pre data-lenis-prevent><code>{`git clone ${REPO}.git && cd ona\n${p.build}`}</code></pre>
      <div className="dl-actions">
        <a className="btn btn-ghost btn-sm" href={`${REPO}/releases/tag/${RELEASE}`}>Release {RELEASE}</a>
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
          <span className="pill"><span className="dot" />Prototype · not audited · no real funds</span>
          <h1>{one ? `Install ONA on ${one.name}.` : "Install ONA."}</h1>
          <p>
            {one ? "This is" : "These are"} the build{one ? "" : "s"} of release {RELEASE}, made on GitHub's machines from the public
            source code. ONA is a prototype: the model, the web and the payments are still simulated in the apps, so do not use
            real funds.
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
