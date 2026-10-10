import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { GUIDES } from "../vite.web.config.js";

const read = (path: string) => readFileSync(new URL(`../web/${path}`, import.meta.url), "utf8");
const FIX_URL = "https://www.upwork.com/freelancers/~01d7446dbecad0fbf2";

describe("guide pages", () => {
  const sitemap = read("public/sitemap.xml");

  for (const slug of GUIDES) {
    const html = read(`${slug}/index.html`);
    const url = `https://lockstamp.github.io/${slug}/`;

    it(`${slug}: canonical, Open Graph, sitemap`, () => {
      expect(html).toContain(`<link rel="canonical" href="${url}" />`);
      expect(html).toContain(`<meta property="og:url" content="${url}" />`);
      expect(html).toMatch(/<meta\s+name="description"/);
      expect(sitemap).toContain(`<loc>${url}</loc>`);
    });

    it(`${slug}: FAQ data is valid JSON and matches the visible questions`, () => {
      const json = html.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/)?.[1];
      const data = JSON.parse(json ?? "");
      expect(data["@type"]).toBe("FAQPage");
      for (const q of data.mainEntity) {
        expect(html).toContain(`<summary>${q.name}</summary>`);
      }
    });

    it(`${slug}: links to the free check and the paid fix, no banned wording`, () => {
      expect(html).toContain('href="../#check"');
      expect(html).toContain(FIX_URL);
      expect(html).not.toMatch(/—|–/);
      expect(html).not.toMatch(/guaranteed|compliant/i);
    });
  }
});
