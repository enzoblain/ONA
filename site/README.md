# ONA website

Three pages, as listed in the root README ("Next steps"): home, demo, downloads. A draft: not deployed.

React with Vite. Commands, Vercel settings and how the demo recording is made are in
[docs/INSTALL.md](../docs/INSTALL.md#the-website). Libraries and versions are in the root
[README](../README.md#libraries-and-ai-generated-code).

The home page opens in 3D (`src/three/world.ts`, drawn with three.js; `src/components/Fall.tsx` holds the slides and the
controls). A liquid ghost stands on a cliff in a forest. "Start" makes it look around and jump into a pit. While
it falls, four slides come up: the camera rests on each one, with the ghost to one side and sometimes in close-up, and
swings round fast between two of them; the pit never stops going past. The slides are driven like the 4ward home page
(wheel, swipe or arrow keys add to a progress value). At the bottom the ghost hits the floor of a dark cave where it is the only light,
splashes into a puddle, then gathers itself again. An "Enter" button then leads to the landing page with the install
links, laid over the cave. There the install cards are large glass panes browsed sideways (`src/components/InstallDeck.tsx`), and the
measured data is a board, one line per figure with its source, date and kind (`src/components/Metrics.tsx`; the layout
borrows from departuremono.com and voidzero.dev). The site is in shades of anthracite grey; only the opening keeps its night blues. With "reduce
motion" on, or on a second visit of the home page, the page starts landed.

Rules this site follows:

- **Every figure has a source and a date**, or is marked as simulated or as an example. Sources are named in
  `src/components/Metrics.tsx`; the demo replays a recorded run (`src/data/demo.json`), it does not invent replies.
- **No third-party request.** Fonts and scripts are bundled, and `vercel.json` sends a content security policy that
  allows this origin only. No cookie, no analytics.
- **No download link to a file that does not exist.** `src/pages/Downloads.tsx` links the installers of the GitHub
  release named in `RELEASE` (v0.1.1); update it and the file names when a new version is published.

Not done yet: a recorded video for the demo page, a social preview image (1200x630), and a check on real phones
(the pages were checked in headless Chrome at 1440x900 and 390x844 only; the swipe on a touch screen and the frame rate on a real phone were not exercised).
