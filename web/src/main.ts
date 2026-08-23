import "./style.css";
import { ApiError, clearKey, storeKey, storedKey } from "./api";
import {
  adapters,
  audit,
  deadLetters,
  destinations,
  endpoints,
  eventDetail,
  events,
  listening,
  unknown,
  type View,
} from "./views";
import { esc } from "./format";

const TABS: { id: string; label: string; view: View }[] = [
  { id: "events", label: "Events", view: events },
  { id: "unknown", label: "Unknown statuses", view: unknown },
  { id: "deadletters", label: "Dead letters", view: deadLetters },
  { id: "endpoints", label: "Endpoints", view: endpoints },
  { id: "destinations", label: "Destinations", view: destinations },
  { id: "adapters", label: "Adapters", view: adapters },
  { id: "listening", label: "Listening", view: listening },
  { id: "audit", label: "Audit", view: audit },
];

const app = document.querySelector<HTMLDivElement>("#app")!;

/** Resolves a hash to a view. `events/<id>` is the one nested route. */
function route(): { tab: string; view: View } {
  const hash = location.hash.slice(1) || "events";
  const [head, rest] = [hash.split("/")[0], hash.split("/").slice(1).join("/")];

  if (head === "events" && rest) return { tab: "events", view: eventDetail(rest) };
  const tab = TABS.find((t) => t.id === head) ?? TABS[0];
  return { tab: tab.id, view: tab.view };
}

function shell(active: string): void {
  app.innerHTML = `
    <header>
      <h1>StatusHub</h1>
      <nav>${TABS.map(
        (t) => `<a href="#${t.id}" class="${t.id === active ? "on" : ""}">${esc(t.label)}</a>`,
      ).join("")}</nav>
      <button id="disconnect" class="quiet">Disconnect</button>
    </header>
    <main id="view"></main>
    <footer><span id="status">connected</span></footer>`;

  app.querySelector<HTMLButtonElement>("#disconnect")!.addEventListener("click", () => {
    clearKey();
    render();
  });
}

function connectScreen(message?: string): void {
  app.innerHTML = `
    <header><h1>StatusHub</h1></header>
    <main>
      <h2>Connect</h2>
      <p class="hint">Paste an API key. It is held in this tab only — never in localStorage, so
        closing the tab ends the session and a shared machine does not keep it.</p>
      ${message ? `<div class="banner error">${esc(message)}</div>` : ""}
      <form id="connect" class="filters">
        <input id="key" type="password" placeholder="sh_live_… or sh_test_…"
               autocomplete="off" spellcheck="false" size="46">
        <button type="submit">Connect</button>
      </form>
    </main>`;

  const form = app.querySelector<HTMLFormElement>("#connect")!;
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const key = app.querySelector<HTMLInputElement>("#key")!.value.trim();
    if (!key) return;
    storeKey(key);
    render();
  });
}

async function render(): Promise<void> {
  if (!storedKey()) {
    connectScreen();
    return;
  }

  const { tab, view } = route();
  shell(tab);

  const el = app.querySelector<HTMLElement>("#view")!;
  const status = app.querySelector<HTMLElement>("#status")!;
  el.innerHTML = `<p class="empty">loading…</p>`;

  try {
    await view(el);
    status.textContent = `connected · ${tab}`;
  } catch (err) {
    // A rejected key returns to the connect screen rather than showing an
    // error inside a shell that cannot load anything — the shell would be a
    // set of tabs that all fail, which reads as a broken dashboard rather
    // than as a wrong credential.
    if (err instanceof ApiError && err.status === 401) {
      clearKey();
      connectScreen(err.message);
      return;
    }
    el.innerHTML = `<div class="banner error">${esc((err as Error).message)}</div>`;
    status.textContent = "error";
  }
}

window.addEventListener("hashchange", () => void render());
void render();
