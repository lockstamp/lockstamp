import { gsap } from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { SplitText } from "gsap/SplitText";
import Lenis from "lenis";

gsap.registerPlugin(ScrollTrigger, SplitText);

declare global {
  interface Window {
    __motionReady?: boolean;
  }
}

const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
let lenis: Lenis | null = null;

// The inspection lamp: `angle` swings it toward the pointer, `power` is how far it has flickered on.
const lamp = { angle: 0, power: 0 };

// Where the lamp hangs (px from the top of the hero, measured from the layout) and half its cone's
// angle (radians). The dust uses it too.
const cone = { apexY: 82, spread: 0.44 };

// Scroll reveals that haven't played yet, so a programmatic jump can finish them instead of
// letting them fire as the page flies past.
const pending = new Map<Element, () => void>();

let measureDrafting = (): void => undefined;

export function startMotion(): void {
  window.__motionReady = true;
  const root = document.documentElement;
  const dark = document.querySelector<HTMLElement>(".dark");
  // If the page already appeared without motion (a slow load), don't hide it again to replay the opening.
  const still = reducedMotion || root.classList.contains("motion-fallback");

  if (dark) drafting(dark);
  if (still) {
    root.classList.add("motion-fallback");
    lamp.power = 1;
    if (dark) dust(dark, false);
    if (!reducedMotion) smoothScroll();
    return;
  }
  smoothScroll();
  if (dark) {
    dust(dark, true);
    aimLamp(dark);
  }
  void opening();
  scrollReveals();
}

// Sections that appear later (progress, results) shift the page; scroll triggers must re-measure.
export function refreshMotion(): void {
  if (!reducedMotion) ScrollTrigger.refresh();
}

// Scrolls through Lenis when it's running, so programmatic scrolls stay smooth and in sync.
export function scrollToElement(el: HTMLElement, block: "start" | "center" = "start"): void {
  if (lenis) {
    const offset = block === "center" ? -(innerHeight - el.offsetHeight) / 2 : -24;
    lenis.scrollTo(el, { offset, duration: 1.1 });
  } else {
    el.scrollIntoView({ behavior: reducedMotion ? "auto" : "smooth", block });
  }
}

// Finishes the reveals above `limit` (or all of them) at once.
export function settleReveals(limit?: HTMLElement): void {
  const edge = limit ? limit.getBoundingClientRect().top : Infinity;
  for (const [el, finish] of [...pending]) {
    if (el.getBoundingClientRect().top >= edge) continue;
    pending.delete(el);
    finish();
  }
}

function smoothScroll(): void {
  lenis = new Lenis({ duration: 1.1, smoothWheel: true });
  lenis.on("scroll", ScrollTrigger.update);
  gsap.ticker.add((time) => lenis?.raf(time * 1000));
  gsap.ticker.lagSmoothing(0);

  for (const link of document.querySelectorAll<HTMLAnchorElement>('a[href^="#"]')) {
    link.addEventListener("click", (event) => {
      const id = link.getAttribute("href") ?? "";
      const target = id.length > 1 ? document.querySelector<HTMLElement>(id) : null;
      if (!target) return;
      event.preventDefault();
      settleReveals(target);
      scrollToElement(target);
      if (link.classList.contains("skip")) target.focus({ preventScroll: true });
      history.replaceState(null, "", id);
    });
  }
}

async function fontsReady(timeout: number): Promise<void> {
  if (!document.fonts) return;
  const loads = Promise.all([
    document.fonts.load('790 100px "Archivo Variable"'),
    document.fonts.load('400 16px "Public Sans Variable"'),
  ]).catch(() => undefined);
  await Promise.race([loads, new Promise((resolve) => setTimeout(resolve, timeout))]);
}

// Distance from the top of `ancestor`, ignoring transforms (the opening moves things while it runs).
function topWithin(el: HTMLElement, ancestor: HTMLElement): number {
  let top = 0;
  for (let node: HTMLElement | null = el; node && node !== ancestor; node = node.offsetParent as HTMLElement | null) {
    top += node.offsetTop;
  }
  return top;
}

// Drafting lines frame the headline's text, like measurements on a blueprint; the lamp hangs just
// above the badge.
function drafting(dark: HTMLElement): void {
  const h1 = dark.querySelector<HTMLElement>(".hero h1");
  const lines = dark.querySelector<HTMLElement>(".drafting");
  const badge = dark.querySelector<HTMLElement>(".badge");
  if (!h1 || !lines) return;
  measureDrafting = () => {
    const box = dark.getBoundingClientRect();
    const head = h1.getBoundingClientRect();
    const range = document.createRange();
    range.selectNodeContents(h1);
    const rects = [...range.getClientRects()].filter((r) => r.width > 1);
    if (rects.length === 0) return;
    const gap = Math.max(10, head.height * 0.07);
    const set = (name: string, value: number) => dark.style.setProperty(name, `${Math.round(value)}px`);
    set("--h1-top", head.top - box.top - gap);
    set("--h1-bottom", head.bottom - box.top + gap);
    set("--h1-left", Math.min(...rects.map((r) => r.left)) - box.left - gap * 1.6);
    set("--h1-right", Math.max(...rects.map((r) => r.right)) - box.left + gap * 1.6);
    lines.classList.add("measured");

    if (badge) {
      // Just above the badge, clear of the nav links; a ~50° beam, like a work lamp.
      cone.apexY = topWithin(badge, dark) - 12;
      set("--beam-top", cone.apexY);
      dark.style.setProperty("--beam-spread", `${((cone.spread * 180) / Math.PI).toFixed(1)}deg`);
    }
  };
  measureDrafting();
  new ResizeObserver(() => measureDrafting()).observe(h1);
  addEventListener("resize", () => measureDrafting());
}

function applyLamp(): void {
  const beam = document.querySelector<HTMLElement>(".beam");
  if (beam) beam.style.opacity = String(lamp.power);
}

// The lamp leans a few degrees toward the pointer, as if someone were aiming it.
function aimLamp(dark: HTMLElement): void {
  const beam = dark.querySelector<HTMLElement>(".beam");
  if (!beam || !matchMedia("(pointer: fine)").matches) return;
  const swing = gsap.quickTo(lamp, "angle", {
    duration: 1.6,
    ease: "power3.out",
    onUpdate: () => beam.style.setProperty("--beam-angle", `${lamp.angle.toFixed(2)}deg`),
  });
  dark.addEventListener("pointermove", (event) => {
    const rect = dark.getBoundingClientRect();
    swing(-((event.clientX - rect.left) / rect.width - 0.5) * 9);
  });
  dark.addEventListener("pointerleave", () => swing(0));
}

// Dust drifting through the lamp's beam: faint everywhere, bright where the light catches it.
function dust(dark: HTMLElement, animate: boolean): void {
  const canvas = dark.querySelector<HTMLCanvasElement>(".dust");
  const ctx = canvas?.getContext("2d");
  if (!canvas || !ctx) return;

  type Mote = { x: number; y: number; r: number; vx: number; vy: number; speed: number; phase: number };
  let motes: Mote[] = [];
  let width = 0;
  let height = 0;
  let clock = 0;

  const draw = () => {
    ctx.clearRect(0, 0, width, height);
    ctx.fillStyle = "rgb(226, 236, 255)";
    const centre = width / 2;
    const axis = (lamp.angle * Math.PI) / 180;
    for (const m of motes) {
      // Angle between the mote and the beam's axis, seen from the lamp.
      const off = Math.abs(Math.atan2(m.x - centre, m.y - cone.apexY) + axis);
      const lit = Math.max(0, 1 - off / cone.spread) ** 1.6;
      const twinkle = 0.65 + 0.35 * Math.sin(clock * 1.2 * m.speed + m.phase);
      const alpha = (0.06 + lit * 0.8 * lamp.power) * twinkle;
      if (alpha < 0.02) continue;
      ctx.globalAlpha = alpha;
      ctx.beginPath();
      ctx.arc(m.x, m.y, m.r * (1 + lit * 0.5), 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.globalAlpha = 1;
  };

  const resize = () => {
    const ratio = Math.min(devicePixelRatio || 1, 1.5);
    width = canvas.clientWidth;
    height = canvas.clientHeight;
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    const count = Math.round(Math.min(170, (width * height) / 8000));
    motes = Array.from({ length: count }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      r: 0.35 + Math.random() ** 2 * 1.4,
      vx: (Math.random() - 0.5) * 0.12,
      vy: -(0.03 + Math.random() * 0.12),
      speed: 0.4 + Math.random() * 1.2,
      phase: Math.random() * Math.PI * 2,
    }));
    draw();
  };

  resize();
  new ResizeObserver(resize).observe(canvas);
  if (!animate) return;

  const tick = (time: number, delta: number) => {
    clock = time;
    const step = Math.min(delta, 50) / 16.7;
    for (const m of motes) {
      m.x += m.vx * step;
      m.y += m.vy * step;
      if (m.y < -4) {
        m.y = height + 4;
        m.x = Math.random() * width;
      }
      if (m.x < -4) m.x = width + 4;
      else if (m.x > width + 4) m.x = -4;
    }
    draw();
  };
  // Only animate while the hero is on screen.
  new IntersectionObserver(([entry]) => {
    if (entry.isIntersecting) gsap.ticker.add(tick);
    else gsap.ticker.remove(tick);
  }).observe(dark);
}

async function opening(): Promise<void> {
  await fontsReady(700);
  const h1 = document.querySelector<HTMLElement>(".hero h1");
  const tl = gsap.timeline({ defaults: { ease: "power3.out" } });

  // The drafting lines rule themselves out from the headline, then the corner marks land.
  tl.set(".drafting", { opacity: 1 }, 0);
  tl.fromTo(".rule-h", { scaleX: 0 }, { scaleX: 1, duration: 1.3, ease: "expo.inOut", stagger: 0.1 }, 0);
  tl.fromTo(".rule-v", { scaleY: 0 }, { scaleY: 1, duration: 1.3, ease: "expo.inOut", stagger: 0.1 }, 0.12);
  tl.fromTo(
    ".tick",
    { scale: 0, rotation: -90, opacity: 0 },
    { scale: 1, rotation: 0, opacity: 1, duration: 0.55, ease: "back.out(2.2)", stagger: 0.06 },
    0.7,
  );

  tl.fromTo(".nav", { y: -16, opacity: 0 }, { y: 0, opacity: 1, duration: 0.7 }, 0.05);
  tl.fromTo(".badge", { y: 14, opacity: 0 }, { y: 0, opacity: 1, duration: 0.7 }, 0.12);

  if (h1) {
    const split = SplitText.create(h1, { type: "words", wordsClass: "word" });
    h1.classList.add("is-split");
    measureDrafting();
    gsap.set(h1, { opacity: 1 });
    tl.fromTo(
      split.words,
      { yPercent: 70, opacity: 0, filter: "blur(14px)" },
      { yPercent: 0, opacity: 1, filter: "blur(0px)", duration: 1.05, stagger: 0.065, ease: "expo.out" },
      0.2,
    );
  }
  tl.fromTo([".lede", ".hero-actions", ".fud"], { y: 18, opacity: 0 }, { y: 0, opacity: 1, duration: 0.8, stagger: 0.08 }, 0.6);

  // The lamp stutters on like a fluorescent tube, lighting the dust in its beam.
  tl.set(".dust", { opacity: 1 }, 0);
  const flicker = gsap.timeline({ onUpdate: applyLamp, defaults: { ease: "none" } });
  flicker
    .to(lamp, { power: 0.55, duration: 0.05 })
    .to(lamp, { power: 0.08, duration: 0.08 })
    .to(lamp, { power: 0.8, duration: 0.05 })
    .to(lamp, { power: 0.25, duration: 0.1 })
    .to(lamp, { power: 1, duration: 0.6, ease: "power2.out" });
  tl.add(flicker, 0.45);

  // Cards rise into the light: the attack ledger in front, the fix and the findings fanned out behind it.
  tl.fromTo(
    ".window",
    { y: 150, opacity: 0, rotationX: 22, scale: 0.92, transformPerspective: 1400 },
    { y: 0, opacity: 1, rotationX: 0, scale: 1, duration: 1.4, ease: "expo.out" },
    0.62,
  );
  tl.fromTo(".side-left", { x: 140, y: 180, rotation: 0, opacity: 0 }, { x: 0, y: 0, rotation: -6, opacity: 1, duration: 1.5, ease: "expo.out" }, 0.8);
  tl.fromTo(".side-right", { x: -140, y: 180, rotation: 0, opacity: 0 }, { x: 0, y: 0, rotation: 6, opacity: 1, duration: 1.5, ease: "expo.out" }, 0.86);

  tl.add(scanSequence(), 1.3);
}

// A scan line sweeps the ledger twice: first marking each attack "Possible", then "Blocked".
// Every step sits at an absolute time, so the whole opening finishes in about four seconds.
function scanSequence(): gsap.core.Timeline {
  const tl = gsap.timeline();
  const body = document.querySelector<HTMLElement>(".window-body");
  const table = body?.querySelector<HTMLTableElement>(".slip");
  const rows = gsap.utils.toArray<HTMLTableRowElement>(".slip tbody tr");
  const verdict = document.querySelector<HTMLElement>(".mock-verdict");
  if (!body || !table || !verdict || rows.length === 0) return tl;

  const line = document.createElement("div");
  line.className = "scanline";
  line.setAttribute("aria-hidden", "true");
  body.append(line);

  const chipsOf = (kind: string) => rows.map((r) => r.querySelector<HTMLElement>(`.chip.${kind}`));
  const possible = chipsOf("possible");
  const blocked = chipsOf("blocked");
  gsap.set([...possible, ...blocked], { opacity: 0 });
  gsap.set([".mock-detail", ".mock-counts"], { opacity: 0, y: 10 });

  // While the scan runs, the verdict reads as a live status instead of an empty gap.
  const finalVerdict = verdict.textContent ?? "";
  verdict.textContent = "Trying attacks…";
  verdict.classList.add("scanning");

  const top = () => table.offsetTop + rows[0].offsetTop - line.offsetHeight;
  const below = (row: HTMLTableRowElement) => table.offsetTop + row.offsetTop + row.offsetHeight - line.offsetHeight;
  const hidden = { opacity: 0, y: 6, scale: 0.9 };
  const shown = { opacity: 1, y: 0, scale: 1, duration: 0.35, ease: "back.out(2)", immediateRender: false };

  // As the line passes a row, its tag appears with a brief glow; on the fix pass the padlock shuts.
  const sweep = (chips: (HTMLElement | null)[], start: number, step: number): number => {
    tl.set(line, { y: top }, start);
    tl.to(line, { opacity: 1, duration: 0.12 }, start);
    rows.forEach((row, i) => {
      const at = start + 0.06 + i * step;
      tl.to(line, { y: () => below(row), duration: step, ease: "power1.inOut" }, at);
      const tag = chips[i];
      if (!tag) return;
      const land = at + step * 0.55;
      tl.fromTo(tag, hidden, shown, land);
      tl.call(() => tag.classList.add("flash"), [], land);
      const shackle = tag.classList.contains("blocked") ? tag.querySelector(".shackle") : null;
      if (shackle) {
        gsap.set(shackle, { y: -3 });
        tl.to(shackle, { y: 0, duration: 0.22, ease: "power2.in" }, land + 0.12);
      }
    });
    const end = start + 0.06 + rows.length * step;
    tl.to(line, { opacity: 0, duration: 0.2 }, end);
    return end;
  };

  const firstDone = sweep(possible, 0, 0.26);
  tl.to(verdict, { opacity: 0, y: -6, duration: 0.16 }, firstDone);
  tl.call(
    () => {
      verdict.textContent = finalVerdict;
      verdict.classList.remove("scanning");
    },
    [],
    firstDone + 0.16,
  );
  tl.fromTo(verdict, { opacity: 0, y: 10 }, { opacity: 1, y: 0, duration: 0.45, immediateRender: false }, firstDone + 0.16);
  tl.to(".mock-counts", { opacity: 1, y: 0, duration: 0.5 }, firstDone + 0.26);

  const fixStart = firstDone + 0.75;
  tl.call(() => line.classList.add("fixing"), [], fixStart);
  const fixDone = sweep(blocked, fixStart, 0.22);
  tl.to(".mock-detail", { opacity: 1, y: 0, duration: 0.5 }, fixDone);
  return tl;
}

function scrollReveals(): void {
  const items = gsap.utils.toArray<HTMLElement>("main .reveal");
  for (const item of items) pending.set(item, () => gsap.set(item, { opacity: 1, y: 0 }));
  ScrollTrigger.batch(items, {
    start: "top 88%",
    once: true,
    onEnter: (batch) => {
      const fresh = (batch as HTMLElement[]).filter((item) => pending.delete(item));
      if (fresh.length > 0) {
        gsap.fromTo(fresh, { y: 44, opacity: 0 }, { y: 0, opacity: 1, duration: 0.9, ease: "power3.out", stagger: 0.08 });
      }
    },
  });

  for (const heading of gsap.utils.toArray<HTMLElement>(".catches h2, .check h2, .privacy h2, .faq h2, .closing h2")) {
    const split = SplitText.create(heading, { type: "words" });
    const tween = gsap.from(split.words, {
      yPercent: 60,
      opacity: 0,
      filter: "blur(8px)",
      duration: 0.85,
      stagger: 0.05,
      ease: "expo.out",
      scrollTrigger: { trigger: heading, start: "top 86%", once: true, onEnter: () => pending.delete(heading) },
    });
    pending.set(heading, () => {
      tween.scrollTrigger?.kill();
      tween.progress(1);
    });
  }

  const counter = document.querySelector<HTMLElement>(".proof [data-count]");
  if (counter) {
    const target = Number(counter.dataset.count);
    const format = (n: number) => Math.round(n).toLocaleString("en-US");
    const state = { value: 0 };
    counter.textContent = format(0);
    const tween = gsap.to(state, {
      value: target,
      duration: 1.8,
      ease: "power2.out",
      paused: true,
      onUpdate: () => {
        counter.textContent = format(state.value);
      },
    });
    const trigger = ScrollTrigger.create({
      trigger: ".proof",
      start: "top 88%",
      once: true,
      onEnter: () => {
        pending.delete(counter);
        tween.play();
      },
    });
    pending.set(counter, () => {
      trigger.kill();
      tween.progress(1);
    });
  }

  const flow = document.querySelector<HTMLElement>(".flow");
  if (flow) {
    const tween = gsap.from(flow.children, {
      x: -16,
      opacity: 0,
      duration: 0.6,
      stagger: 0.12,
      ease: "power2.out",
      scrollTrigger: { trigger: flow, start: "top 85%", once: true, onEnter: () => pending.delete(flow) },
    });
    pending.set(flow, () => {
      tween.scrollTrigger?.kill();
      tween.progress(1);
    });
  }
}
