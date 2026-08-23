// The views.
//
// Each renders into the element it is handed and does its own fetching, so a
// view that fails does so alone rather than blanking the shell around it.

import * as api from "./api";
import { ago, clip, esc, money, ms, when } from "./format";

export type View = (el: HTMLElement) => Promise<void>;

function table(head: string[], rows: string[]): string {
  if (rows.length === 0) return "";
  return `<table>
    <thead><tr>${head.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead>
    <tbody>${rows.join("")}</tbody>
  </table>`;
}

function empty(message: string): string {
  return `<p class="empty">${esc(message)}</p>`;
}

function statusCell(e: api.Event): string {
  // Colour is never the only signal: the word is always present, so the
  // column is readable by somebody who cannot distinguish the colours and
  // survives being pasted into a chat window as text.
  const flags = [
    e.mapping_complete === false ? `<span class="flag">mapping incomplete</span>` : "",
    e.unmapped_status ? `<span class="flag">unmapped: ${esc(e.unmapped_status)}</span>` : "",
    e.redacted ? `<span class="flag">redacted</span>` : "",
  ].join("");
  return `<span class="status ${esc(e.status)}">${esc(e.status)}</span>${flags}`;
}

// --- events ------------------------------------------------------------------

/**
 * The event explorer. The screen somebody opens at 2am.
 *
 * Everything it filters on is something an engineer types during an incident:
 * a transaction reference from a customer complaint, a provider behaving
 * oddly, or mapping_complete=false to see what StatusHub itself is unsure
 * about.
 */
export const events: View = async (el) => {
  el.innerHTML = `
    <h2>Events</h2>
    <p class="hint">Every event, in the shape your destination received it. Search by transaction
      reference when a customer asks about one payment; filter on <em>mapping incomplete</em> to
      see what StatusHub could not fully read.</p>
    <form class="filters" id="f">
      <input name="transaction_ref" placeholder="transaction reference" autocomplete="off">
      <input name="provider" placeholder="provider" autocomplete="off">
      <select name="status">
        <option value="">any status</option>
        ${["pending", "success", "failed", "reversed", "abandoned", "unknown"]
          .map((s) => `<option>${s}</option>`)
          .join("")}
      </select>
      <select name="mapping_complete">
        <option value="">any mapping</option>
        <option value="false">incomplete only</option>
        <option value="true">complete only</option>
      </select>
      <button type="submit">Search</button>
    </form>
    <div id="out" class="empty">searching…</div>`;

  const form = el.querySelector<HTMLFormElement>("#f")!;
  const out = el.querySelector<HTMLDivElement>("#out")!;

  const search = async () => {
    const params = new URLSearchParams();
    for (const [k, v] of new FormData(form).entries()) {
      if (typeof v === "string" && v.trim()) params.set(k, v.trim());
    }
    params.set("limit", "100");

    out.className = "empty";
    out.textContent = "searching…";
    const data = await api.events(params.toString());
    const rows = data.events ?? [];
    if (rows.length === 0) {
      out.textContent = "no matching events";
      return;
    }

    out.className = "";
    out.innerHTML = table(
      ["occurred (UTC)", "provider", "transaction ref", "status", "amount", "event"],
      rows.map(
        (e) => `<tr data-id="${esc(e.event_id)}" class="clickable">
          <td class="mono">${esc(when(e.occurred_at))}</td>
          <td>${esc(e.provider)}</td>
          <td class="mono">${esc(e.transaction_ref)}</td>
          <td>${statusCell(e)}</td>
          <td class="num">${esc(money(e.amount_minor, e.currency))}</td>
          <td class="mono">${esc(clip(e.event_id, 30))}</td>
        </tr>`,
      ),
    );

    for (const tr of out.querySelectorAll<HTMLTableRowElement>("tr[data-id]")) {
      tr.addEventListener("click", () => {
        location.hash = `events/${tr.dataset.id}`;
      });
    }
  };

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    void search().catch((err) => {
      out.className = "empty";
      out.textContent = String(err.message ?? err);
    });
  });
  await search();
};

/** One event, with every delivery attempt. */
export function eventDetail(id: string): View {
  return async (el) => {
    const d = await api.event(id);
    const e = d.event;

    el.innerHTML = `
      <p><a href="#events">← events</a></p>
      <h2>${esc(e.transaction_ref)}</h2>
      <div class="cards">
        <div class="card"><div class="n">${statusCell(e)}</div><div class="l">status</div></div>
        <div class="card"><div class="n">${esc(money(e.amount_minor, e.currency))}</div><div class="l">amount</div></div>
        <div class="card"><div class="n">${esc(e.provider)}</div><div class="l">provider</div></div>
        <div class="card"><div class="n">${esc(d.delivery_count)}</div><div class="l">delivery attempts</div></div>
      </div>

      <h3>Canonical event</h3>
      <p class="hint">This is exactly what your destination received — the same bytes, rendered.</p>
      <pre>${esc(JSON.stringify(e, null, 2))}</pre>

      <h3>Deliveries</h3>
      ${
        (d.deliveries ?? []).length === 0
          ? empty(
              "no delivery attempts. Either no destination matched this event, or it has not been " +
                "queued yet — both are visible under Destinations.",
            )
          : table(
              ["created (UTC)", "destination", "attempt", "status", "code", "took", "response"],
              d.deliveries.map(
                (v) => `<tr>
                  <td class="mono">${esc(when(v.created_at))}</td>
                  <td class="mono">${esc(clip(v.destination_id, 22))}</td>
                  <td class="num">${esc(v.attempt)}${v.is_replay ? '<span class="flag">replay</span>' : ""}</td>
                  <td><span class="status ${esc(v.status)}">${esc(v.status)}</span></td>
                  <td class="num">${esc(v.response_code ?? "—")}</td>
                  <td class="num">${esc(ms(v.duration_ms))}</td>
                  <td class="mono">${esc(clip(v.response_body || v.error || "", 90))}</td>
                </tr>`,
              ),
            )
      }

      <p><button id="replay">Replay this event</button>
        <span class="hint">Sent again with <code>X-StatusHub-Replay: true</code> and the same
        idempotency key, so a handler that already processed it recognises it.</span></p>
      <p id="replay-out" class="hint"></p>`;

    el.querySelector<HTMLButtonElement>("#replay")!.addEventListener("click", async (ev) => {
      const btn = ev.currentTarget as HTMLButtonElement;
      const out = el.querySelector<HTMLElement>("#replay-out")!;
      btn.disabled = true;
      try {
        await api.replay(id);
        out.textContent = "queued. It will be delivered within a second or two.";
      } catch (err) {
        out.textContent = `could not replay: ${(err as Error).message}`;
        btn.disabled = false;
      }
    });
  };
}

// --- unknown statuses ---------------------------------------------------------

/** The to-do list the product generates for itself. */
export const unknown: View = async (el) => {
  const d = await api.unknownStatuses();
  const rows = d.unknown_statuses ?? [];

  el.innerHTML = `
    <h2>Unknown statuses</h2>
    <p class="hint">Provider status values with no mapping, most frequent first. Events carrying
      them were forwarded as <code>unknown</code> rather than guessed at — mapping an unrecognised
      value to <em>failed</em> is how a fintech reverses a payment that succeeded.</p>
    ${
      rows.length === 0
        ? empty("nothing unmapped. Every provider value seen recently has a mapping.")
        : table(
            ["provider", "value", "seen", "first", "last", "sample event"],
            rows.map(
              (u) => `<tr>
                <td>${esc(u.provider)}</td>
                <td class="mono">${esc(u.raw_value)}</td>
                <td class="num">${esc(u.count)}</td>
                <td class="mono">${esc(when(u.first_seen))}</td>
                <td class="mono">${esc(when(u.last_seen))}</td>
                <td class="mono"><a href="#events/${esc(u.sample_event_id)}">${esc(clip(u.sample_event_id, 26))}</a></td>
              </tr>`,
            ),
          )
    }`;
};

// --- dead letters --------------------------------------------------------------

export const deadLetters: View = async (el) => {
  const d = await api.deadLetters();
  const rows = d.deliveries ?? [];

  el.innerHTML = `
    <h2>Dead letters</h2>
    <p class="hint">Deliveries that exhausted their retry budget. Nothing is lost: retrying creates
      a <em>new</em> delivery rather than overwriting this record, because the failure is the
      evidence of what the destination said and when.</p>
    ${
      rows.length === 0
        ? empty("no dead letters.")
        : table(
            ["created (UTC)", "destination", "attempts", "code", "response", ""],
            rows.map(
              (v) => `<tr>
                <td class="mono">${esc(when(v.created_at))}</td>
                <td class="mono">${esc(clip(v.destination_id, 22))}</td>
                <td class="num">${esc(v.attempt)}</td>
                <td class="num">${esc(v.response_code ?? "—")}</td>
                <td class="mono">${esc(clip(v.response_body || v.error || "", 80))}</td>
                <td><button data-retry="${esc(v.id)}">Retry</button></td>
              </tr>`,
            ),
          )
    }`;

  for (const btn of el.querySelectorAll<HTMLButtonElement>("button[data-retry]")) {
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      btn.textContent = "queued";
      await api.retryDelivery(Number(btn.dataset.retry));
    });
  }
};

// --- endpoints -----------------------------------------------------------------

export const endpoints: View = async (el) => {
  const d = await api.endpoints();
  const rows = d.endpoints ?? [];

  el.innerHTML = `
    <h2>Endpoints</h2>
    <p class="hint">The URLs you paste into each provider's dashboard. Rotating a token changes only
      the token, not the shape of the URL — so a rotation is a one-line edit on their side.</p>
    ${
      rows.length === 0
        ? empty("no endpoints yet.")
        : rows
            .map(
              (e) => `<div class="card wide">
                <div><strong>${esc(e.provider)}</strong> · ${esc(e.environment)} ·
                  adapter ${esc(e.adapter)}
                  ${e.enabled ? "" : '<span class="flag">disabled</span>'}</div>
                <pre>${esc(e.receiver_url)}</pre>
                <div class="l">secret reference <code>${esc(e.secret_ref)}</code> — StatusHub stores
                  the reference, never the secret</div>
                ${
                  e.warning
                    ? `<p class="hint warn"><span class="flag">weaker guarantee</span> ${esc(e.warning)}</p>`
                    : ""
                }
              </div>`,
            )
            .join("")
    }`;
};

// --- destinations ----------------------------------------------------------------

export const destinations: View = async (el) => {
  const d = await api.destinations();
  const rows = d.destinations ?? [];

  el.innerHTML = `
    <h2>Destinations</h2>
    <p class="hint">Where events are forwarded. Each keeps the schema version it was created with:
      a newer version never moves an existing handler on its own.</p>
    ${
      rows.length === 0
        ? empty(
            "no destinations. Events are still stored and searchable — nothing is being forwarded.",
          )
        : table(
            ["name", "url", "schema", "retry schedule", "raw"],
            rows.map(
              (v) => `<tr>
                <td>${esc(v.name || "—")}</td>
                <td class="mono">${esc(v.url)}</td>
                <td class="mono">${esc(v.schema_version)}</td>
                <td class="mono">${esc((v.retry_schedule ?? []).join(", "))}</td>
                <td>${v.include_raw ? "included" : ""}</td>
              </tr>`,
            ),
          )
    }`;
};

// --- adapters ----------------------------------------------------------------------

export const adapters: View = async (el) => {
  const d = await api.adapters();

  el.innerHTML = `
    <h2>Adapters</h2>
    <p class="hint">Each documents its own signature scheme — including where that scheme is weaker
      than the others. Worth reading before relying on one.</p>
    ${d.adapters
      .map(({ built_in, description: a }) => {
        if (a.error) {
          return `<div class="card wide">
            <div><strong>${esc(a.name)}</strong> <span class="flag">does not load</span></div>
            <div class="l">${esc(a.error)}</div></div>`;
        }
        return `<div class="card wide">
          <div><strong>${esc(a.display_name || a.name)}</strong>
            ${built_in ? "" : '<span class="flag">yours</span>'}
            · amounts in ${esc(a.amount_unit)} units
            · ${a.supplies_event_id ? "supplies an event ID" : "no event ID — dedupes on the body hash"}</div>
          <div class="l">${esc(a.signature_scheme)}</div>
          ${a.notes ? `<p class="hint">${esc(a.notes)}</p>` : ""}
        </div>`;
      })
      .join("")}`;
};

// --- listening -----------------------------------------------------------------------

export const listening: View = async (el) => {
  const d = await api.listening();
  const rows = d.sessions ?? [];

  el.innerHTML = `
    <h2>Listening</h2>
    <p class="hint">Developers streaming live events to their own machines with
      <code>statushubctl listen</code>. Events are copied, never diverted — your real destinations
      keep receiving everything. Shown here because a laptop receiving live production payloads is
      something the whole team should be able to see.</p>
    ${
      rows.length === 0
        ? empty("nobody is listening.")
        : table(
            ["session", "forwarding to", "started", "last seen", "delivered", "failed"],
            rows.map(
              (s) => `<tr>
                <td class="mono">${esc(clip(s.id, 24))}</td>
                <td class="mono">${esc(s.forward || "—")}</td>
                <td class="mono">${esc(when(s.started_at))}</td>
                <td class="mono">${esc(ago(s.last_seen))}</td>
                <td class="num">${esc(s.delivered)}</td>
                <td class="num">${esc(s.failed)}</td>
              </tr>`,
            ),
          )
    }`;
};

// --- audit -----------------------------------------------------------------------------

export const audit: View = async (el) => {
  const [proof, log] = await Promise.all([api.auditVerify(), api.audit()]);
  const rows = log.records ?? [];

  // An empty chain is not a pass. It verifies trivially, and a green tick
  // would claim an audit trail is intact when there is no audit trail.
  const verdict =
    proof.records === 0
      ? { text: "no records", cls: "warn" }
      : proof.intact
        ? { text: "intact", cls: "ok" }
        : { text: "BROKEN", cls: "bad" };

  el.innerHTML = `
    <h2>Audit</h2>
    <div class="cards">
      <div class="card"><div class="n ${verdict.cls}">${esc(verdict.text)}</div><div class="l">hash chain</div></div>
      <div class="card"><div class="n">${esc(proof.records)}</div><div class="l">records</div></div>
      <div class="card"><div class="n mono small">${esc(clip(proof.head_hash, 22))}</div><div class="l">head</div></div>
    </div>
    ${
      proof.records === 0
        ? `<div class="banner">An empty chain verifies trivially. That is not the same as an intact
             audit trail, so it is not reported as one.</div>`
        : ""
    }
    ${
      !proof.intact && proof.records > 0
        ? `<div class="banner error">Chain broken at ${esc(proof.broken_at)}: ${esc(proof.reason)}.
             This is a security incident — preserve state and escalate. Do not restart anything.</div>`
        : ""
    }
    <p class="hint">Every state change, hash-chained per tenant. Corrections are appended, never
      applied: a wrong record stays, followed by one that explains it.</p>
    ${
      rows.length === 0
        ? empty("no records in this window.")
        : table(
            ["recorded (UTC)", "event", "actor", "subject"],
            rows.map(
              (r) => `<tr>
                <td class="mono">${esc(when(r.recorded_at))}</td>
                <td>${esc(r.event_type)}${r.corrects ? '<span class="flag">correction</span>' : ""}</td>
                <td class="mono">${esc(r.actor?.type)}${r.actor?.id ? " " + esc(clip(r.actor.id, 20)) : ""}</td>
                <td class="mono">${esc(r.subject?.type)} ${esc(clip(r.subject?.id, 26))}</td>
              </tr>`,
            ),
          )
    }`;
};
