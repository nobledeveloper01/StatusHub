/*
  StatusHub dashboard.
 
  Vanilla, no build step, no dependencies. Eight screens of tables and forms
  do not justify a bundler, and every dependency here would be one more thing
  a fintech's security team has to approve before they can look at their own
  webhooks.
 
  The event explorer is the screen that matters. Everything else is
  configuration; that one is what somebody opens at 2am.
*/
'use strict';

const state = {
  key: sessionStorage.getItem('statushub.key') || '',
  view: location.hash.slice(1) || 'events',
};

const VIEWS = [
  ['events', 'Events'],
  ['unknown', 'Unknown statuses'],
  ['deadletters', 'Dead letters'],
  ['endpoints', 'Endpoints'],
  ['destinations', 'Destinations'],
  ['adapters', 'Adapters'],
  ['listen', 'Listening'],
  ['audit', 'Audit'],
];

// --- plumbing ---------------------------------------------------------------

async function api(path, options = {}) {
  if (!state.key) throw new Error('connect with an API key first');
  const resp = await fetch(path, {
    ...options,
    headers: {
      Authorization: `Bearer ${state.key}`,
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
  if (resp.status === 401) {
    throw new Error('the API key was not accepted');
  }
  if (resp.status === 403) {
    throw new Error('this key does not have the role that route requires');
  }
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}));
    throw new Error(body.error || `${resp.status} from ${path}`);
  }
  return resp.status === 204 ? null : resp.json();
}

// Everything user-controlled goes through here. Provider names, status values
// and adapter names are all data somebody else chose, and a dashboard that
// renders them as HTML is a stored-XSS bug in an operations console.
function esc(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}

function el(id) { return document.getElementById(id); }

function banner(message, isError) {
  const b = el('banner');
  if (!message) { b.hidden = true; return; }
  b.hidden = false;
  b.className = isError ? 'banner error' : 'banner';
  b.textContent = message;
}

function money(minor, currency) {
  if (minor === 0 && !currency) return '';
  // Rendered from integer minor units without going near a float, because
  // this column is read against a ledger.
  const negative = minor < 0;
  const digits = String(Math.abs(minor)).padStart(3, '0');
  const value = `${digits.slice(0, -2)}.${digits.slice(-2)}`;
  return `${negative ? '-' : ''}${value} ${esc(currency || '')}`.trim();
}

function when(iso) {
  if (!iso) return '';
  // Always UTC, always the same width, so a column of them is scannable and
  // nobody has to wonder whose timezone they are reading.
  return String(iso).replace('T', ' ').replace(/\.\d+/, '').replace('Z', '');
}

// --- views ------------------------------------------------------------------

const views = {};

views.events = async () => {
  const q = new URLSearchParams(location.search);
  render(`
    <h2>Event explorer</h2>
    <p class="hint">Every event, in the same shape your destination received it.
      Search by transaction reference when a customer asks about one payment; filter on
      <code>mapping_complete=false</code> to see what StatusHub itself was unsure about.</p>
    <div class="filters">
      <input id="f-ref" placeholder="transaction reference" value="${esc(q.get('transaction_ref') || '')}">
      <input id="f-provider" placeholder="provider">
      <select id="f-status">
        <option value="">any status</option>
        ${['pending', 'success', 'failed', 'reversed', 'abandoned', 'unknown']
          .map((s) => `<option>${s}</option>`).join('')}
      </select>
      <select id="f-mapping">
        <option value="">any mapping</option>
        <option value="false">incomplete only</option>
        <option value="true">complete only</option>
      </select>
      <button id="f-go">Search</button>
    </div>
    <div id="results" class="empty">searching…</div>
  `);

  const search = async () => {
    const params = new URLSearchParams();
    const add = (k, v) => { if (v) params.set(k, v); };
    add('transaction_ref', el('f-ref').value.trim());
    add('provider', el('f-provider').value.trim());
    add('status', el('f-status').value);
    add('mapping_complete', el('f-mapping').value);
    params.set('limit', '100');

    try {
      const data = await api(`/v1/events?${params}`);
      const rows = data.events || [];
      if (rows.length === 0) {
        el('results').className = 'empty';
        el('results').textContent = 'no matching events';
        return;
      }
      el('results').className = '';
      el('results').innerHTML = `
        <table>
          <thead><tr>
            <th>occurred (UTC)</th><th>provider</th><th>transaction ref</th>
            <th>status</th><th class="num">amount</th><th>event</th>
          </tr></thead>
          <tbody>${rows.map(eventRow).join('')}</tbody>
        </table>`;
    } catch (err) {
      banner(err.message, true);
      el('results').textContent = '';
    }
  };

  el('f-go').addEventListener('click', search);
  el('f-ref').addEventListener('keydown', (e) => { if (e.key === 'Enter') search(); });
  await search();
};

function eventRow(e) {
  // mapping_complete and unmapped_status are surfaced in the row rather than
  // buried in a detail pane. They are the whole reason an engineer opens this
  // screen after a provider changes something.
  const flags = [
    e.mapping_complete === false ? '<span class="flag">mapping incomplete</span>' : '',
    e.unmapped_status ? `<span class="flag">unmapped: ${esc(e.unmapped_status)}</span>` : '',
    e.redacted ? '<span class="flag">redacted</span>' : '',
  ].join('');
  return `<tr>
    <td class="mono">${esc(when(e.occurred_at))}</td>
    <td>${esc(e.provider)}</td>
    <td class="mono">${esc(e.transaction_ref)}</td>
    <td><span class="status ${esc(e.status)}">${esc(e.status)}</span>${flags}</td>
    <td class="num">${money(e.amount_minor, e.currency)}</td>
    <td class="mono">${esc(e.event_id)}</td>
  </tr>`;
}

views.unknown = async () => {
  const data = await api('/v1/unknown-statuses');
  const rows = data.unknown_statuses || [];
  render(`
    <h2>Unknown statuses</h2>
    <p class="hint">Provider status values with no mapping, most frequent first. Events carrying
      them were forwarded with status <code>unknown</code> rather than guessed at — mapping an
      unrecognised value to <em>failed</em> is how a fintech reverses a payment that succeeded.
      This is the list of adapter work worth doing next.</p>
    ${rows.length === 0
      ? '<p class="empty">nothing unmapped. Every provider value seen recently has a mapping.</p>'
      : `<table><thead><tr>
           <th>provider</th><th>value</th><th class="num">seen</th>
           <th>first</th><th>last</th><th>sample event</th>
         </tr></thead><tbody>${rows.map((u) => `<tr>
           <td>${esc(u.provider)}</td>
           <td class="mono">${esc(u.raw_value)}</td>
           <td class="num">${esc(u.count)}</td>
           <td class="mono">${esc(when(u.first_seen))}</td>
           <td class="mono">${esc(when(u.last_seen))}</td>
           <td class="mono">${esc(u.sample_event_id)}</td>
         </tr>`).join('')}</tbody></table>`}
  `);
};

views.deadletters = async () => {
  const data = await api('/v1/deliveries?status=dead_letter&limit=100');
  const rows = data.deliveries || [];
  render(`
    <h2>Dead letters</h2>
    <p class="hint">Deliveries that exhausted their retry budget. Nothing is lost: each one can be
      retried, and retrying creates a new delivery rather than overwriting this record — the
      failure is evidence of what the destination said and when.</p>
    ${rows.length === 0
      ? '<p class="empty">no dead letters.</p>'
      : `<table><thead><tr>
           <th>created (UTC)</th><th>event</th><th>destination</th>
           <th class="num">attempts</th><th class="num">code</th><th>response</th>
         </tr></thead><tbody>${rows.map((d) => `<tr>
           <td class="mono">${esc(when(d.CreatedAt || d.created_at))}</td>
           <td class="mono">${esc(d.EventID || d.event_id)}</td>
           <td class="mono">${esc(d.DestinationID || d.destination_id)}</td>
           <td class="num">${esc(d.Attempt ?? d.attempt)}</td>
           <td class="num">${esc(d.ResponseCode ?? d.response_code ?? '')}</td>
           <td class="mono">${esc((d.ResponseBody ?? d.response_body ?? '').slice(0, 120))}</td>
         </tr>`).join('')}</tbody></table>`}
  `);
};

views.endpoints = async () => {
  const data = await api('/v1/endpoints');
  const rows = data.endpoints || [];
  render(`
    <h2>Endpoints</h2>
    <p class="hint">The URLs you paste into each provider's dashboard. Rotating a token changes only
      the token, not the shape of the URL — so a rotation is a one-line edit on their side.</p>
    ${rows.length === 0
      ? '<p class="empty">no endpoints yet.</p>'
      : rows.map((e) => `
        <div class="card" style="margin-bottom:0.75rem">
          <div><strong>${esc(e.provider)}</strong> · ${esc(e.environment)} · adapter ${esc(e.adapter)}
            ${e.enabled ? '' : '<span class="flag">disabled</span>'}</div>
          <pre>${esc(e.receiver_url)}</pre>
          <div class="l">secret reference ${esc(e.secret_ref)} — StatusHub stores the reference, never the secret</div>
          ${e.warning ? `<p class="hint" style="margin-top:0.5rem"><span class="flag">weaker guarantee</span> ${esc(e.warning)}</p>` : ''}
        </div>`).join('')}
  `);
};

views.destinations = async () => {
  const data = await api('/v1/destinations');
  const rows = data.destinations || [];
  render(`
    <h2>Destinations</h2>
    <p class="hint">Where events are forwarded. Each keeps the schema version it was created with:
      a new version never moves an existing handler on its own.</p>
    ${rows.length === 0
      ? '<p class="empty">no destinations yet. Events are stored and searchable, but nothing is being forwarded.</p>'
      : `<table><thead><tr>
           <th>name</th><th>url</th><th>schema</th><th>retry schedule</th><th>raw</th>
         </tr></thead><tbody>${rows.map((d) => `<tr>
           <td>${esc(d.name || '—')}</td>
           <td class="mono">${esc(d.url)}</td>
           <td class="mono">${esc(d.schema_version)}</td>
           <td class="mono">${esc((d.retry_schedule || []).join(', '))}</td>
           <td>${d.include_raw ? 'included' : ''}</td>
         </tr>`).join('')}</tbody></table>`}
  `);
};

views.adapters = async () => {
  const data = await api('/v1/adapters');
  const rows = data.adapters || [];
  render(`
    <h2>Adapters</h2>
    <p class="hint">Each adapter documents its own signature scheme — including where that scheme is
      weaker than the others. Worth reading before you rely on one.</p>
    ${rows.map((a) => {
      const d = a.description || {};
      if (d.error) {
        return `<div class="card" style="margin-bottom:0.75rem">
          <div><strong>${esc(d.name)}</strong> <span class="flag">does not load</span></div>
          <div class="l">${esc(d.error)}</div></div>`;
      }
      return `<div class="card" style="margin-bottom:0.75rem">
        <div><strong>${esc(d.display_name || d.name)}</strong>
          ${a.built_in ? '' : '<span class="flag">yours</span>'}
          · amounts in ${esc(d.amount_unit)} units
          · ${d.supplies_event_id ? 'supplies an event ID' : 'no event ID — dedupes on the body hash'}</div>
        <div class="l">${esc(d.signature_scheme)}</div>
        ${d.notes ? `<p class="hint" style="margin:0.5rem 0 0">${esc(d.notes)}</p>` : ''}
      </div>`;
    }).join('')}
  `);
};

views.listen = async () => {
  const data = await api('/v1/listen');
  const rows = data.sessions || [];
  render(`
    <h2>Listening</h2>
    <p class="hint">Developers streaming live events to their own machines with
      <code>statushubctl listen</code>. Events are copied, never diverted — your real destinations
      keep receiving everything. Shown here because a laptop receiving live production payloads is
      something the whole team should be able to see.</p>
    ${rows.length === 0
      ? '<p class="empty">nobody is listening.</p>'
      : `<table><thead><tr>
           <th>session</th><th>forwarding to</th><th>started</th><th>last seen</th>
           <th class="num">delivered</th><th class="num">failed</th>
         </tr></thead><tbody>${rows.map((s) => `<tr>
           <td class="mono">${esc(s.id)}</td>
           <td class="mono">${esc(s.forward || '—')}</td>
           <td class="mono">${esc(when(s.started_at))}</td>
           <td class="mono">${esc(when(s.last_seen))}</td>
           <td class="num">${esc(s.delivered)}</td>
           <td class="num">${esc(s.failed)}</td>
         </tr>`).join('')}</tbody></table>`}
  `);
};

views.audit = async () => {
  const [proof, log] = await Promise.all([
    // A broken chain returns 409, so it is caught rather than rendered as a
    // field somebody has to notice.
    fetch('/v1/audit/verify', { headers: { Authorization: `Bearer ${state.key}` } })
      .then((r) => r.json()),
    api('/v1/audit?limit=100'),
  ]);
  const rows = log.records || [];
  render(`
    <h2>Audit</h2>
    <div class="cards">
      <div class="card"><div class="n">${proof.intact ? 'intact' : 'BROKEN'}</div><div class="l">hash chain</div></div>
      <div class="card"><div class="n">${esc(proof.records ?? 0)}</div><div class="l">records</div></div>
    </div>
    ${proof.intact ? '' : `<div class="banner error">Chain broken at ${esc(proof.broken_at)}: ${esc(proof.reason)}. This is a security incident — preserve state and escalate.</div>`}
    <p class="hint">Every state change, hash-chained per tenant. Corrections are appended, never
      applied: a wrong record stays, followed by one that explains it.</p>
    ${rows.length === 0
      ? '<p class="empty">no records in this window.</p>'
      : `<table><thead><tr>
           <th>recorded (UTC)</th><th>event</th><th>actor</th><th>subject</th>
         </tr></thead><tbody>${rows.map((r) => `<tr>
           <td class="mono">${esc(when(r.recorded_at))}</td>
           <td>${esc(r.event_type)}</td>
           <td class="mono">${esc(r.actor?.type)}${r.actor?.id ? ' ' + esc(r.actor.id) : ''}</td>
           <td class="mono">${esc(r.subject?.type)} ${esc(r.subject?.id)}</td>
         </tr>`).join('')}</tbody></table>`}
  `);
};

// --- shell ------------------------------------------------------------------

function render(html) { el('view').innerHTML = html; }

function drawNav() {
  el('nav').innerHTML = VIEWS.map(([id, label]) =>
    `<button data-view="${id}"${state.view === id ? ' aria-current="page"' : ''}>${label}</button>`).join('');
  for (const b of el('nav').querySelectorAll('button')) {
    b.addEventListener('click', () => { location.hash = b.dataset.view; });
  }
}

async function show() {
  drawNav();
  banner('');
  if (!state.key) {
    render(`<h2>Connect</h2>
      <p class="hint">Paste an API key above. It is held in this tab only — never written to
        localStorage, so closing the tab ends the session and a shared machine does not keep it.</p>`);
    el('status').textContent = 'not connected';
    return;
  }
  const view = views[state.view] || views.events;
  try {
    el('status').textContent = 'loading…';
    await view();
    el('status').textContent = `connected · ${state.view}`;
  } catch (err) {
    banner(err.message, true);
    render('');
    el('status').textContent = 'error';
  }
}

el('connect').addEventListener('click', () => {
  state.key = el('apikey').value.trim();
  // sessionStorage, not localStorage: an API key that survives a closed tab
  // on a shared machine is a key somebody else finds.
  sessionStorage.setItem('statushub.key', state.key);
  show();
});
el('apikey').addEventListener('keydown', (e) => { if (e.key === 'Enter') el('connect').click(); });

window.addEventListener('hashchange', () => {
  state.view = location.hash.slice(1) || 'events';
  show();
});

el('apikey').value = state.key;
show();
