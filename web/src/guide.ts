// Guide pages are plain reading pages: the fonts and the shared look, no checker or animation.
import "@fontsource-variable/archivo/wdth.css";
import "@fontsource-variable/public-sans/wght.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "./styles.css";
import "./guide.css";

// A copy button on every SQL block, so nobody has to select a block that scrolls sideways.
const status = document.createElement("span");
status.className = "sr-only";
status.setAttribute("aria-live", "polite");
document.body.append(status);

for (const pre of document.querySelectorAll<HTMLPreElement>(".prose pre")) {
  const heading = pre.closest(".cause")?.querySelector("h3") ?? findLabel(pre);
  const wrap = document.createElement("div");
  wrap.className = "code-wrap";
  pre.replaceWith(wrap);
  wrap.append(pre);
  const button = document.createElement("button");
  button.type = "button";
  button.className = "copy-code";
  button.textContent = "Copy";
  button.setAttribute("aria-label", `Copy SQL: ${heading?.textContent?.trim() ?? "code"}`);
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(pre.innerText.trim());
      button.textContent = "Copied";
      status.textContent = "Copied";
    } catch {
      button.textContent = "Select and copy";
    }
    setTimeout(() => (button.textContent = "Copy"), 1800);
  });
  wrap.append(button);
}

// The nearest label or heading above a code block, to name its copy button.
function findLabel(el: Element): Element | null {
  for (let node = el.previousElementSibling; node; node = node.previousElementSibling) {
    if (node.matches("h2, h3, .label")) return node;
  }
  return null;
}
