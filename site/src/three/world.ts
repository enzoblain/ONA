import * as THREE from "three";
import gsap from "gsap";
import { MarchingCubes } from "three/examples/jsm/objects/MarchingCubes.js";
import { RoomEnvironment } from "three/examples/jsm/environments/RoomEnvironment.js";

// The 3D world of the home page opening.
//
// The ghost never moves: it sits at the origin and the world goes up past it. `scroll` is how far it has
// fallen. A forest with a cliff is at the top, a pit with rock walls in between, a dark cave at the bottom.
// The ghost is liquid: a set of blobs, each one pulled towards its place in the ghost's shape, drawn as one smooth
// surface (metaballs). On impact the blobs become free drops that splash and settle into a puddle, then they are
// pulled back into shape from the feet up.

export type Phase = "intro" | "starting" | "falling" | "landing" | "landed";

export const SLIDES = 4;
const FEET = -1.25; // height of the ghost's hem, in ghost units
const WALL_PERIOD = 10;
const WALL_RADIUS = 13;

type Pose = { az: number; r: number; h: number; ox: number; oy: number };

// Camera stops. `az` turns around the ghost, `r` is the distance (a small `r` is a close-up), `h` the height.
// `ox` and `oy` push the ghost off-centre, in half-screens: the text of a slide takes the other side.
const POSE: Record<string, Pose> = {
  intro: { az: 0.5, r: 10.5, h: 1.4, ox: 0, oy: -0.12 },
  land: { az: 0.4, r: 10, h: 2.6, ox: 0, oy: 0.12 },
  hero: { az: 0, r: 9.6, h: 0.7, ox: 0, oy: -0.5 },
};
const SLIDE_POSES: Pose[] = [
  { az: -0.75, r: 8.2, h: 0.5, ox: 0.46, oy: 0 }, // from the left, ghost on the left
  { az: 0.85, r: 5.2, h: 0.3, ox: -0.48, oy: 0.03 }, // swing right, close-up
  { az: -0.55, r: 9.6, h: 3.2, ox: 0.46, oy: 0 }, // swing left, from above
  { az: 0.7, r: 4.6, h: -0.6, ox: -0.5, oy: 0.06 }, // swing right, close-up from below
];

const smooth = (a: number, b: number, x: number) => {
  const t = Math.min(1, Math.max(0, (x - a) / (b - a)));
  return t * t * (3 - 2 * t);
};
const mix = (a: number, b: number, t: number) => a + (b - a) * t;
const mixPose = (a: Pose, b: Pose, t: number): Pose => ({
  az: mix(a.az, b.az, t), r: mix(a.r, b.r, t), h: mix(a.h, b.h, t), ox: mix(a.ox, b.ox, t), oy: mix(a.oy, b.oy, t),
});
const rand = (a: number, b: number) => a + Math.random() * (b - a);

// ---------- The ghost's shape, as blobs that fill it ----------

const EYE_Y = 0.62;

function ghostBlobs() {
  const pos: number[] = [], radius: number[] = [], drop: number[] = [];
  const HEAD_Y = 0.55;
  // The blobs sit inside the shape: the surface forms about one blob radius further out.
  const inside = (x: number, y: number, z: number) => {
    if (y > HEAD_Y) return x * x + z * z + (y - HEAD_Y) * (y - HEAD_Y) < 0.6 * 0.6;
    if (y < -0.86) return false;
    return Math.hypot(x, z) < 0.6 + 0.13 * smooth(0, 1, (HEAD_Y - y) / 1.7);
  };
  for (let tries = 0; radius.length < 150 && tries < 60000; tries++) {
    const x = rand(-0.8, 0.8), y = rand(-0.9, 1.2), z = rand(-0.8, 0.8);
    if (!inside(x, y, z)) continue;
    let free = true;
    for (let i = 0; i < radius.length && free; i++) {
      free = Math.hypot(x - pos[i * 3], y - pos[i * 3 + 1], z - pos[i * 3 + 2]) > 0.23;
    }
    if (!free) continue;
    pos.push(x, y, z); radius.push(rand(0.31, 0.36)); drop.push(0);
  }
  // The hem: six lobes that hang and drip.
  for (let k = 0; k < 6; k++) {
    const a = (k * Math.PI) / 3;
    pos.push(Math.cos(a) * 0.74, -1.0, Math.sin(a) * 0.74); radius.push(0.23); drop.push(0);
  }
  // Two stubby arms.
  for (const side of [-1, 1]) { pos.push(side * 1.02, -0.05, 0.12); radius.push(0.25); drop.push(0); }
  // Drops that come off the top of the head while it falls. At rest they are inside the head.
  for (let i = 0; i < 14; i++) { pos.push(rand(-0.45, 0.45), 0.95, rand(-0.45, 0.45)); radius.push(rand(0.1, 0.16)); drop.push(1); }
  return { pos: new Float32Array(pos), radius: new Float32Array(radius), drop: new Uint8Array(drop) };
}

// ---------- The world ----------

export function createWorld(canvas: HTMLCanvasElement, opts: { reduced: boolean }) {
  const small = Math.min(window.innerWidth, window.innerHeight) < 600;
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, powerPreference: "high-performance" });
  renderer.setPixelRatio(Math.min(small ? 1.5 : 2, window.devicePixelRatio || 1));
  renderer.localClippingEnabled = true;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;

  const scene = new THREE.Scene();
  const NIGHT = new THREE.Color("#0b1230"), PIT = new THREE.Color("#04050c"), CAVE = new THREE.Color("#0d0e10");
  const GLOW_FALL = new THREE.Color("#8fa0ff"), GLOW_CAVE = new THREE.Color("#eceef2");
  const BODY_FALL = new THREE.Color("#e8ebff"), BODY_CAVE = new THREE.Color("#f1f1f3");
  const ROCK_FALL = new THREE.Color("#2b3049"), ROCK_CAVE = new THREE.Color("#33343a");
  const air = new THREE.Color().copy(NIGHT);
  scene.background = air;
  const fog = new THREE.FogExp2(air.getHex(), 0.026);
  scene.fog = fog;
  const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 260);

  // What the page drives, and what the timelines animate.
  const st = {
    phase: "intro" as Phase,
    q: 0, // progress through the slides, already smoothed (0 .. SLIDES)
    qSpeed: 0, // slides per second
    scroll: 0, // distance fallen
    speed: 0, // current falling speed
    pose: { ...POSE.intro },
    lookX: 0, lookY: 0, blink: 1,
    squash: 1, hop: 0, jump: 0, // jump: how far the cliff has moved away behind the ghost
    wind: 0, // 0 standing, 1 falling: the hem flaps and drops come off the head
    cave: 0, // 0 in the pit, 1 in the cave (air colour, the ghost's glow)
    shake: 0,
    spread: 0, // 0: the liquid is the ghost; 1: it is splashed over the floor (the drawn volume is wider)
    face: 1, // the eyes and the mouth: 1 shown, 0 gone
    glitch: 0, // above 0, the ghost is drawn in shifted slices; the value changes with each step of a glitch
    floor: -1e4, // world height of the cave floor
    mode: "formed" as "formed" | "scatter" | "reform",
    reformAt: 0,
  };

  // ----- Lights -----
  const hemi = new THREE.HemisphereLight("#93a4ff", "#0a0c18", 0.55);
  scene.add(hemi);
  const moon = new THREE.DirectionalLight("#a9bbff", 1.5);
  moon.position.set(-30, 34, -70);
  scene.add(moon);
  const head = new THREE.DirectionalLight("#ffffff", 1.1); // follows the camera, so the liquid keeps its relief
  scene.add(head, head.target);
  const aura = new THREE.PointLight("#8fa0ff", 14, 16, 1.8); // the ghost lights what is near it
  scene.add(aura);

  // The pit only exists below the forest floor and above the cave floor.
  const clipTop = new THREE.Plane(new THREE.Vector3(0, -1, 0), FEET);
  const clipBottom = new THREE.Plane(new THREE.Vector3(0, 1, 0), 1e4);
  const clips = [clipTop, clipBottom];

  // ----- The ghost: a liquid body, and a face that floats on it -----
  const ISO = 80, SUB = 12;
  const pmrem = new THREE.PMREMGenerator(renderer);
  const reflections = pmrem.fromScene(new RoomEnvironment(), 0.04).texture; // something for the liquid to reflect
  pmrem.dispose();
  const liquid = new THREE.MeshPhysicalMaterial({
    color: "#e8ebff", roughness: 0.08, metalness: 0.05, clearcoat: 1, clearcoatRoughness: 0.05,
    iridescence: 0.45, iridescenceIOR: 1.3, envMap: reflections, envMapIntensity: 0.75,
    emissive: "#aab4ff", emissiveIntensity: 0.06,
  });
  const blob = new MarchingCubes(small ? 50 : 76, liquid, false, false, 90000);
  blob.isolation = ISO;
  blob.frustumCulled = false;
  scene.add(blob);

  const shape = ghostBlobs();
  const n = shape.radius.length;
  const P = new Float32Array(n * 3), V = new Float32Array(n * 3);
  const seed = new Float32Array(n), hem = new Float32Array(n);
  for (let i = 0; i < n; i++) {
    seed[i] = Math.random();
    hem[i] = smooth(0.2, -1.0, shape.pos[i * 3 + 1]);
    P[i * 3] = shape.pos[i * 3]; P[i * 3 + 1] = shape.pos[i * 3 + 1]; P[i * 3 + 2] = shape.pos[i * 3 + 2];
  }

  const face = new THREE.Group();
  const ink = new THREE.MeshStandardMaterial({ color: "#06070f", roughness: 0.25 });
  const glint = new THREE.MeshBasicMaterial({ color: "#d5dcff", toneMapped: false, fog: false });
  const eyes = [-1, 1].map((side) => {
    const eye = new THREE.Group();
    eye.position.set(side * 0.3, EYE_Y, 0.83);
    eye.rotation.y = side * 0.33;
    const socket = new THREE.Mesh(new THREE.SphereGeometry(1, 20, 14), ink);
    socket.scale.set(0.125, 0.18, 0.06);
    const pupil = new THREE.Mesh(new THREE.SphereGeometry(0.04, 12, 10), glint);
    pupil.position.set(0.03, 0.06, 0.055);
    eye.add(socket, pupil);
    face.add(eye);
    return { eye, pupil };
  });
  const smile = new THREE.Mesh(new THREE.TorusGeometry(0.1, 0.026, 8, 18, Math.PI), ink);
  smile.position.set(0, 0.34, 0.955);
  smile.rotation.z = Math.PI;
  face.add(smile);
  scene.add(face);

  // ----- The pit: a rock wall that repeats, rocks sticking out of it, speed lines -----
  const rockMat = new THREE.MeshStandardMaterial({ color: "#2b3049", roughness: 1, flatShading: true, clippingPlanes: clips, side: THREE.DoubleSide });
  const wallGeo = (() => {
    const g = new THREE.CylinderGeometry(WALL_RADIUS, WALL_RADIUS, WALL_PERIOD * 9, 44, 63, true);
    const waves = Array.from({ length: 7 }, () => ({ m: Math.round(rand(2, 9)), k: Math.round(rand(1, 4)), a: rand(0.1, 0.26), p: rand(0, 6.28) }));
    const at = g.attributes.position;
    for (let i = 0; i < at.count; i++) {
      const x = at.getX(i), y = at.getY(i), z = at.getZ(i), ang = Math.atan2(z, x);
      // Whole numbers of waves around the pit and per period, so that the wall repeats without a seam.
      let d = 0;
      for (const w of waves) d += w.a * Math.sin(w.m * ang + (w.k * 2 * Math.PI * y) / WALL_PERIOD + w.p);
      const r = WALL_RADIUS - 0.4 + d;
      at.setXYZ(i, Math.cos(ang) * r, y, Math.sin(ang) * r);
    }
    const flat = g.toNonIndexed();
    flat.computeVertexNormals();
    return flat;
  })();
  const wall = new THREE.Mesh(wallGeo, rockMat);
  scene.add(wall);

  const ROCKS = small ? 90 : 170, ROCK_SPAN = 70;
  const rocks = new THREE.InstancedMesh(new THREE.DodecahedronGeometry(1, 0), rockMat, ROCKS);
  rocks.frustumCulled = false;
  const rockData = Array.from({ length: ROCKS }, () => {
    const a = rand(0, 6.28), r = rand(11.9, 12.8); // outside the widest camera orbit (10.5)
    return {
      x: Math.cos(a) * r, z: Math.sin(a) * r, y: rand(-ROCK_SPAN / 2, ROCK_SPAN / 2),
      q: new THREE.Quaternion().setFromEuler(new THREE.Euler(rand(0, 6), rand(0, 6), rand(0, 6))),
      s: new THREE.Vector3(rand(0.5, 1.1), rand(0.7, 2.6), rand(0.5, 1.1)),
    };
  });
  scene.add(rocks);

  const LINES = small ? 70 : 150, LINE_SPAN = 44;
  const lineGeo = new THREE.BufferGeometry();
  const linePos = new Float32Array(LINES * 6);
  const lineData = Array.from({ length: LINES }, () => {
    const a = rand(0, 6.28), r = rand(2.2, 11);
    return { x: Math.cos(a) * r, z: Math.sin(a) * r, y: rand(-LINE_SPAN / 2, LINE_SPAN / 2), k: rand(0.5, 1.4) };
  });
  lineGeo.setAttribute("position", new THREE.BufferAttribute(linePos, 3));
  const lineMat = new THREE.LineBasicMaterial({ color: "#aab6ff", transparent: true, opacity: 0, clippingPlanes: clips });
  const lines = new THREE.LineSegments(lineGeo, lineMat);
  lines.frustumCulled = false;
  scene.add(lines);

  // ----- The top: a forest at night, and the cliff the ghost stands on -----
  const forest = new THREE.Group();
  scene.add(forest);
  {
    const ground = new THREE.MeshStandardMaterial({ color: "#0d2419", roughness: 1, flatShading: true });
    const ring = new THREE.Mesh(new THREE.RingGeometry(WALL_RADIUS - 0.6, 90, 56), ground);
    ring.rotation.x = -Math.PI / 2;
    ring.position.y = FEET;
    const cliff = new THREE.Mesh(new THREE.BoxGeometry(7, 44, 14), new THREE.MeshStandardMaterial({ color: "#272c44", roughness: 1, flatShading: true }));
    cliff.position.set(0, FEET - 22.12, -6.1);
    const grass = new THREE.Mesh(new THREE.BoxGeometry(7.3, 0.24, 14.3), ground);
    grass.position.set(0, FEET - 0.12, -6.1);
    forest.add(ring, cliff, grass);

    // Pines: three cones on a trunk. A few on the cliff, the rest around the pit.
    const spots: { x: number; z: number; s: number }[] = [];
    for (let i = 0; i < 9; i++) spots.push({ x: rand(-3, 3), z: rand(-12.5, -2.2), s: rand(0.8, 1.5) });
    for (let i = 0; i < (small ? 70 : 150); i++) {
      const a = rand(0, 6.28), r = rand(14.5, 60);
      spots.push({ x: Math.cos(a) * r, z: Math.sin(a) * r, s: rand(0.9, 2.4) });
    }
    const leaf = new THREE.MeshStandardMaterial({ color: "#ffffff", roughness: 1, flatShading: true });
    const cones = new THREE.InstancedMesh(new THREE.ConeGeometry(1, 2.2, 7), leaf, spots.length * 3);
    const trunks = new THREE.InstancedMesh(new THREE.CylinderGeometry(0.13, 0.18, 1.2, 6), new THREE.MeshStandardMaterial({ color: "#2a1d16", roughness: 1 }), spots.length);
    const m = new THREE.Matrix4(), q = new THREE.Quaternion(), tint = new THREE.Color();
    spots.forEach((t, i) => {
      trunks.setMatrixAt(i, m.compose(new THREE.Vector3(t.x, FEET + 0.6 * t.s, t.z), q, new THREE.Vector3(t.s, t.s, t.s)));
      for (let tier = 0; tier < 3; tier++) {
        const w = (1.25 - tier * 0.3) * t.s;
        m.compose(new THREE.Vector3(t.x, FEET + (1.7 + tier * 1.15) * t.s, t.z), q.setFromAxisAngle(new THREE.Vector3(0, 1, 0), rand(0, 6)), new THREE.Vector3(w, t.s, w));
        cones.setMatrixAt(i * 3 + tier, m);
        cones.setColorAt(i * 3 + tier, tint.setHSL(rand(0.38, 0.45), rand(0.35, 0.5), rand(0.1, 0.17)));
      }
    });
    forest.add(cones, trunks);

    const starPos = new Float32Array(500 * 3);
    for (let i = 0; i < 500; i++) {
      const a = rand(0, 6.28), e = rand(0.04, 1.3);
      starPos.set([Math.cos(a) * Math.cos(e) * 180, Math.sin(e) * 180, Math.sin(a) * Math.cos(e) * 180], i * 3);
    }
    const starGeo = new THREE.BufferGeometry();
    starGeo.setAttribute("position", new THREE.BufferAttribute(starPos, 3));
    forest.add(new THREE.Points(starGeo, new THREE.PointsMaterial({ color: "#dfe6ff", size: 1.6, sizeAttenuation: false, fog: false, transparent: true, opacity: 0.8 })));
    const disc = new THREE.Mesh(new THREE.SphereGeometry(7, 24, 16), new THREE.MeshBasicMaterial({ color: "#e9eeff", fog: false }));
    disc.position.set(-52, 58, -120);
    forest.add(disc);
  }

  // ----- The bottom: a cave floor and stalagmites. No lamp down here: the ghost is the light. -----
  const cave = new THREE.Group();
  cave.visible = false;
  scene.add(cave);
  {
    const stone = new THREE.MeshStandardMaterial({ color: "#3b3c40", roughness: 1, flatShading: true });
    const floor = new THREE.Mesh(new THREE.CircleGeometry(WALL_RADIUS + 1.5, 40), stone);
    floor.rotation.x = -Math.PI / 2;
    cave.add(floor);
    // The camera stands on the +z side (angles around a quarter turn): that sector stays empty up to the wall.
    const spot = (rMin: number, rMax: number) => {
      for (;;) {
        const a = rand(0, 6.28), r = rand(rMin, rMax);
        if (a > 0.15 && a < 3.0 && r < 11.6) continue;
        return { a, r };
      }
    };
    for (let i = 0; i < 26; i++) {
      const { a, r } = spot(5, 12.5), h = rand(0.8, 4.4);
      const spike = new THREE.Mesh(new THREE.ConeGeometry(rand(0.3, 0.9), h, 6), stone);
      spike.position.set(Math.cos(a) * r, h / 2, Math.sin(a) * r);
      spike.rotation.set(rand(-0.12, 0.12), rand(0, 6), rand(-0.12, 0.12));
      cave.add(spike);
    }
    for (let i = 0; i < 30; i++) {
      const { a, r } = spot(2.4, 12);
      const pebble = new THREE.Mesh(new THREE.DodecahedronGeometry(rand(0.08, 0.3), 0), stone);
      pebble.position.set(Math.cos(a) * r, 0.05, Math.sin(a) * r);
      cave.add(pebble);
    }
  }

  // ----- Frame -----
  const dummy = new THREE.Matrix4(), v3 = new THREE.Vector3(), target = new THREE.Vector3();
  let width = 1, height = 1, aspect = 1;
  const resize = () => {
    width = canvas.clientWidth || 1;
    height = canvas.clientHeight || 1;
    aspect = width / height;
    renderer.setSize(width, height, false);
    camera.aspect = aspect;
    camera.fov = aspect < 0.85 ? 64 : 42; // on a narrow screen the ghost must still fit the width
    camera.updateProjectionMatrix();
  };

  // The pose for the current progress: it rests on each slide and swings to the next one in between.
  const swing = { amount: 0, dir: 1 };
  const fallingPose = (): Pose => {
    const u = st.q - 0.5; // slide i is centred at u = i
    if (u <= 0) {
      swing.amount = Math.sin(Math.PI * smooth(0, 1, st.q * 2));
      swing.dir = -1;
      return mixPose(POSE.intro, SLIDE_POSES[0], smooth(0, 1, st.q * 2));
    }
    const i = Math.min(SLIDES - 1, Math.floor(u)), f = u - i;
    if (i >= SLIDES - 1) { swing.amount = smooth(0, 0.5, f); return SLIDE_POSES[SLIDES - 1]; }
    const w = smooth(0.26, 0.74, f);
    swing.amount = Math.sin(Math.PI * w);
    swing.dir = i % 2 ? -1 : 1;
    return mixPose(SLIDE_POSES[i], SLIDE_POSES[i + 1], w);
  };

  // Sideways shift of the slice at height y, for one step of a glitch. About half of the slices do not move.
  const slice = (y: number, step: number) => {
    const h = Math.sin(Math.floor((y + 2) * 5.5) * 12.9898 + step * 78.233) * 43758.5453;
    const f = h - Math.floor(h) - 0.5;
    return Math.abs(f) < 0.22 ? 0 : f * 1.35;
  };

  const flow = (dt: number, t: number) => {
    const yaw = st.pose.az * 0.55, cy = Math.cos(yaw), sy = Math.sin(yaw);
    const follow = 1 - Math.exp(-dt * 20);
    const since = t - st.reformAt;
    const wide = 1 + (1 - st.squash) * 0.9;
    const bob = st.wind < 0.5 && st.mode === "formed" ? Math.sin(t * 1.6) * 0.07 * (1 - st.wind) : 0;

    // The volume the surface is computed in: tight around the ghost, wider when the liquid is on the floor.
    const half = mix(2.2, 5.4, st.spread);
    const midY = FEET + half * 0.62 + st.hop; // follows the jump; the floor, when there is one, is at the ghost's feet
    blob.scale.setScalar(half);
    blob.position.set(0, midY, 0);
    blob.reset();

    for (let i = 0; i < n; i++) {
      const j = i * 3, ph = seed[i] * 6.283;
      let size = shape.radius[i];
      if (st.mode === "scatter") {
        // free drops: gravity, a floor, a little bounce, then they stick and spread
        V[j + 1] -= 16 * dt;
        P[j] += V[j] * dt; P[j + 1] += V[j + 1] * dt; P[j + 2] += V[j + 2] * dt;
        const rest = st.floor + 0.05;
        if (P[j + 1] < rest) {
          P[j + 1] = rest;
          V[j + 1] = Math.abs(V[j + 1]) > 1.2 ? -V[j + 1] * 0.22 : 0;
          const grip = Math.exp(-dt * 4.5);
          V[j] *= grip; V[j + 2] *= grip;
        }
      } else {
        // where this blob belongs in the ghost, right now
        let x = shape.pos[j], y = shape.pos[j + 1], z = shape.pos[j + 2];
        const flap = hem[i] * st.wind;
        x += flap * 0.1 * Math.sin(t * 6 + ph) + Math.sin(t * 1.3 + ph) * 0.012;
        z += flap * 0.1 * Math.cos(t * 5.3 + ph * 1.7) + Math.cos(t * 1.1 + ph) * 0.012;
        y += flap * (0.2 + 0.13 * Math.sin(t * 8 + ph * 2)) + Math.sin(t * 1.7 + ph) * 0.02;
        if (hem[i] > 0.9) y += Math.sin(t * 2.1 + ph) * 0.05; // the hem drips a little, even at rest
        if (shape.drop[i]) {
          // drops leave the top of the head while it falls, and thin out as they rise
          const life = (t * (0.5 + seed[i] * 0.6) + seed[i] * 9) % 1;
          y += life * 1.25 * st.wind;
          x += Math.sin(ph + life * 4) * 0.35 * life * st.wind;
          z += Math.cos(ph * 1.3 + life * 3) * 0.35 * life * st.wind;
          size *= 1 - life * 0.55 * st.wind;
        }
        x *= wide; z *= wide;
        y = FEET + (y - FEET) * st.squash + st.hop + bob;
        const wx = x * cy + z * sy, wz = -x * sy + z * cy;
        if (st.mode === "reform") {
          // pulled back into shape, feet first
          const wait = ((shape.pos[j + 1] - FEET) / 2.7) * 0.85 + seed[i] * 0.3;
          const pull = Math.min(1, Math.max(0, (since - wait) / 0.55));
          if (pull > 0) {
            const a = 1 - Math.exp(-dt * (1.5 + 11 * pull));
            P[j] += (wx - P[j]) * a; P[j + 1] += (y - P[j + 1]) * a; P[j + 2] += (wz - P[j + 2]) * a;
          }
        } else {
          P[j] += (wx - P[j]) * follow; P[j + 1] += (y - P[j + 1]) * follow; P[j + 2] += (wz - P[j + 2]) * follow;
        }
      }
      // A glitch cuts the ghost into horizontal slices and shifts some of them sideways; a few blobs drop out.
      let gx = 0;
      if (st.glitch > 0) {
        gx = slice(P[j + 1], st.glitch);
        if (Math.abs(Math.sin(seed[i] * 91 + st.glitch * 7)) > 0.93) continue;
      }
      // into the volume: 0..1 on each axis
      const bx = (P[j] + gx) / (2 * half) + 0.5, by = (P[j + 1] - midY) / (2 * half) + 0.5, bz = P[j + 2] / (2 * half) + 0.5;
      if (bx < 0.03 || bx > 0.97 || by < 0.03 || by > 0.97 || bz < 0.03 || bz > 0.97) continue;
      const rn = size / (2 * half);
      blob.addBall(bx, by, bz, rn * rn * (ISO + SUB) * 0.5, SUB);
    }
    blob.update();

    // The face rides on the body.
    face.visible = st.face > 0.01;
    face.position.set(st.glitch > 0 ? slice(EYE_Y, st.glitch) : 0, FEET * (1 - st.squash) + st.hop + bob, 0);
    if (st.glitch > 0 && Math.sin(st.glitch * 5.3) > 0.55) face.visible = false;
    face.rotation.y = yaw;
    face.scale.set(wide * st.face, st.squash * st.face, Math.max(1.03, wide) * st.face); // never sinks into the body when it stretches
    for (const { eye, pupil } of eyes) {
      eye.scale.y = st.blink;
      pupil.position.set(0.03 + st.lookX * 0.05, 0.06 + st.lookY * 0.07, 0.055);
    }
  };

  let raf = 0, last = performance.now(), visible = true, blinkAt = 3, glitchAt = 0, glitchUntil = 0;
  const frame = (now: number) => {
    raf = 0;
    const dt = Math.min(0.05, (now - last) / 1000), t = now / 1000;
    last = now;

    if (st.phase === "falling") {
      Object.assign(st.pose, fallingPose());
      // Never still: slow on a slide, fast between two slides, faster again when the reader pushes.
      const want = 5.5 + 30 * swing.amount + 34 * Math.min(1.5, st.qSpeed);
      st.speed += (want - st.speed) * Math.min(1, dt * 5);
    }
    if (st.phase === "starting" || st.phase === "falling") st.scroll += st.speed * dt;

    // Camera: around the ghost, with the ghost pushed off-centre, a slow drift, a roll in the swings, a shake on impact.
    const narrow = aspect < 0.85;
    const pose = st.pose;
    const r = narrow ? 7.4 + pose.r * 0.25 : pose.r; // narrow screens: a wider lens (see resize), and never outside the pit wall
    const az = pose.az + Math.sin(t * 0.37) * 0.05, h = pose.h + Math.sin(t * 0.51) * 0.1;
    const halfH = r * Math.tan((camera.fov * Math.PI) / 360), halfW = halfH * aspect;
    const ox = narrow ? 0 : pose.ox, oy = narrow && st.phase === "falling" ? -0.48 : pose.oy;
    camera.position.set(Math.sin(az) * r, h, Math.cos(az) * r);
    target.set(Math.cos(az) * ox * halfW, oy * halfH, -Math.sin(az) * ox * halfW);
    if (st.shake > 0) camera.position.add(v3.set(rand(-1, 1), rand(-1, 1), rand(-1, 1)).multiplyScalar(st.shake * 0.28));
    camera.up.set(Math.sin(st.phase === "falling" ? swing.amount * swing.dir * 0.16 : 0), 1, 0);
    camera.lookAt(target);
    head.position.copy(camera.position);

    // Air: night blue in the forest, black in the pit, warm in the cave.
    const deep = smooth(4, 55, st.scroll);
    air.copy(NIGHT).lerp(PIT, deep).lerp(CAVE, st.cave);
    fog.color.copy(air);
    fog.density = mix(0.02, 0.034, deep);
    moon.intensity = mix(1.5, 0.12, deep) * (1 - st.cave);
    hemi.intensity = mix(0.55, 0.3, deep);

    // Forest and cliff: go up with the scroll; the cliff also backs away as the ghost jumps.
    forest.visible = st.scroll < 140;
    forest.position.set(0, st.scroll, -st.jump);
    clipTop.constant = FEET + st.scroll - 0.05;

    // Pit wall, rocks, speed lines: all wrap around.
    wall.position.y = st.scroll % WALL_PERIOD;
    for (let i = 0; i < ROCKS; i++) {
      const rock = rockData[i];
      const y = ((((rock.y + st.scroll + ROCK_SPAN / 2) % ROCK_SPAN) + ROCK_SPAN) % ROCK_SPAN) - ROCK_SPAN / 2;
      rocks.setMatrixAt(i, dummy.compose(v3.set(rock.x, y, rock.z), rock.q, rock.s));
    }
    rocks.instanceMatrix.needsUpdate = true;
    const streak = Math.min(2.6, st.speed * 0.045);
    for (let i = 0; i < LINES; i++) {
      const line = lineData[i];
      const y = ((((line.y + st.scroll * line.k + LINE_SPAN / 2) % LINE_SPAN) + LINE_SPAN) % LINE_SPAN) - LINE_SPAN / 2;
      linePos.set([line.x, y, line.z, line.x, y + streak * line.k, line.z], i * 6);
    }
    lineGeo.attributes.position.needsUpdate = true;
    lineMat.opacity = Math.min(0.55, st.speed * 0.016) * (st.phase === "landed" ? 0 : 1);

    // Cave.
    cave.position.y = st.floor;
    clipBottom.constant = -st.floor;
    // In the cave the ghost is the only light: it glows, and its glow reaches the walls. Dim while it is a puddle.
    const glow = st.cave * (0.35 + 0.65 * st.face);
    aura.intensity = mix(14, 150, glow) * (1 + Math.sin(t * 2.3) * 0.04);
    aura.distance = mix(16, 34, st.cave);
    aura.position.y = mix(0, 0.5, st.cave);
    aura.color.copy(GLOW_FALL).lerp(GLOW_CAVE, st.cave); // lavender in the pit, a neutral white in the grey cave
    liquid.emissive.copy(aura.color);
    liquid.color.copy(BODY_FALL).lerp(BODY_CAVE, st.cave);
    rockMat.color.copy(ROCK_FALL).lerp(ROCK_CAVE, st.cave);
    liquid.emissiveIntensity = mix(0.06, 0.55, glow);
    head.intensity = mix(1.1, 0.35, st.cave);
    hemi.intensity *= 1 - st.cave * 0.7;

    // On the landing page the ghost glitches now and then: a short burst of steps, each one a new set of slices.
    if (st.phase === "landed" && !opts.reduced) {
      if (glitchAt === 0) glitchAt = t + rand(1.5, 3); // not right at the landing
      else if (t > glitchAt) { glitchUntil = t + rand(0.16, 0.5); glitchAt = t + rand(2.4, 7); }
      st.glitch = t < glitchUntil ? 1 + Math.floor(t * 13) : 0;
    } else st.glitch = 0;
    liquid.emissiveIntensity *= st.glitch > 0 ? 1.6 : 1;

    // Blink now and then.
    if (st.phase !== "starting" && t > blinkAt) {
      blinkAt = t + rand(2.2, 6);
      gsap.to(st, { blink: 0.12, duration: 0.07, yoyo: true, repeat: 1 });
    }

    flow(dt, t);
    renderer.render(scene, camera);
    if (visible && !(opts.reduced && st.phase === "landed")) raf = requestAnimationFrame(frame);
  };
  const wake = () => { if (!raf) { last = performance.now(); raf = requestAnimationFrame(frame); } };

  const observer = new IntersectionObserver((entries) => {
    visible = entries[0].isIntersecting;
    if (visible) wake();
  });
  observer.observe(canvas);
  const onResize = () => { resize(); wake(); };
  window.addEventListener("resize", onResize);
  resize();
  wake();

  let timeline: gsap.core.Timeline | null = null;

  // While it waits on the cliff, the ghost looks left, then right, with a glance down into the pit now and then.
  const idle = gsap.timeline({ repeat: -1, delay: 0.6 })
    .to(st, { lookX: -1, duration: 0.35, ease: "power2.inOut" })
    .to(st, { lookX: 1, duration: 0.5, ease: "power2.inOut" }, "+=0.9")
    .to(st, { lookX: 0, lookY: -1, duration: 0.35, ease: "power2.inOut" }, "+=0.9")
    .to(st, { lookY: 0, duration: 0.3, ease: "power2.inOut" }, "+=0.7")
    .to({}, { duration: 0.5 });

  return {
    state: st,

    // Crouch and jump straight away (the looking around happens before, while waiting). The cliff backs away and
    // goes up: we fall with the ghost.
    start(onFalling: () => void) {
      st.phase = "starting";
      idle.kill();
      timeline = gsap.timeline()
        .to(st, { lookX: 0, lookY: -1, duration: 0.14, ease: "power2.out" }, 0)
        .to(st, { squash: 0.72, duration: 0.2, ease: "power2.out" }, 0)
        .to(st, { squash: 1.12, hop: 1.1, duration: 0.34, ease: "power2.out" }, 0.2)
        .to(st, { jump: 4.2, duration: 0.9, ease: "power1.out" }, 0.2)
        .to(st, { hop: 0, squash: 1, duration: 0.45, ease: "power2.in" }, 0.54)
        .to(st, { speed: 26, wind: 1, duration: 0.85, ease: "power2.in" }, 0.5)
        .to(st, { lookY: 0, duration: 0.4 }, 0.8)
        .add(() => { st.phase = "falling"; onFalling(); }, 1.25);
    },

    // The cave floor arrives at full speed. Impact: the liquid splashes into a puddle. Then it gathers into the ghost again.
    land(onArrived: () => void) {
      st.phase = "landing";
      const gap = Math.max(34, st.speed * 0.9 + 22), from = st.scroll;
      const sink = { d: 0 };
      cave.visible = true;
      timeline?.kill();
      timeline = gsap.timeline()
        .to(sink, {
          d: gap, duration: 0.95, ease: "none",
          onUpdate: () => { st.scroll = from + sink.d; st.floor = FEET - gap + sink.d; },
        }, 0)
        .to(st.pose, { ...POSE.land, duration: 0.95, ease: "power2.inOut" }, 0)
        .to(st, { cave: 1, duration: 0.95, ease: "power2.in" }, 0)
        .add(() => {
          st.speed = 0; st.wind = 0; st.mode = "scatter"; st.shake = 1; st.lookX = 0; st.lookY = 0;
          for (let i = 0; i < n; i++) {
            const j = i * 3, out = Math.hypot(P[j], P[j + 2]) || 1, push = rand(0.4, 3.4);
            V[j] = (P[j] / out) * push + rand(-1, 1); V[j + 2] = (P[j + 2] / out) * push + rand(-1, 1);
            V[j + 1] = rand(0.5, 5) * (0.4 + (P[j + 1] - FEET) / 3);
          }
        }, 0.95)
        .to(st, { shake: 0, duration: 0.55, ease: "power2.out" }, 0.95)
        .to(st, { spread: 1, duration: 0.12, ease: "power2.out" }, 0.9)
        .set(st, { face: 0 }, 0.95)
        .to(st, { spread: 0, duration: 1.3, ease: "power2.inOut" }, 3.3)
        .to(st, { face: 1, duration: 0.5, ease: "back.out(2)" }, 4.6)
        .add(() => { st.mode = "reform"; st.reformAt = performance.now() / 1000; }, 2.7)
        .add(() => { st.mode = "formed"; }, 4.75)
        .add(() => onArrived(), 5.2);
    },

    // From the cave to the pages: the camera rises to the view the landing page is laid over.
    enter(onDone: () => void) {
      timeline?.kill();
      timeline = gsap.timeline()
        .to(st.pose, { ...POSE.hero, duration: 1.5, ease: "power2.inOut" }, 0)
        .add(() => { st.phase = "landed"; onDone(); }, 1.5);
    },

    // Straight to the end state, without the fall.
    landed() {
      timeline?.kill();
      idle.kill();
      st.lookX = 0; st.lookY = 0;
      Object.assign(st, { phase: "landed", scroll: 400, speed: 0, wind: 0, cave: 1, floor: FEET, mode: "formed", jump: 4.2, shake: 0 });
      Object.assign(st.pose, POSE.hero);
      cave.visible = true;
      wake();
    },

    dispose() {
      timeline?.kill();
      idle.kill();
      cancelAnimationFrame(raf);
      observer.disconnect();
      window.removeEventListener("resize", onResize);
      scene.traverse((o) => {
        const mesh = o as THREE.Mesh;
        mesh.geometry?.dispose();
        const mat = mesh.material as THREE.Material | THREE.Material[] | undefined;
        if (Array.isArray(mat)) mat.forEach((x) => x.dispose());
        else mat?.dispose();
      });
      renderer.dispose();
    },
  };
}

export type World = ReturnType<typeof createWorld>;
