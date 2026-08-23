var A=Object.defineProperty;var N=(e,n,a)=>n in e?A(e,n,{enumerable:!0,configurable:!0,writable:!0,value:a}):e[n]=a;var _=(e,n,a)=>N(e,typeof n!="symbol"?n+"":n,a);(function(){const n=document.createElement("link").relList;if(n&&n.supports&&n.supports("modulepreload"))return;for(const r of document.querySelectorAll('link[rel="modulepreload"]'))t(r);new MutationObserver(r=>{for(const i of r)if(i.type==="childList")for(const d of i.addedNodes)d.tagName==="LINK"&&d.rel==="modulepreload"&&t(d)}).observe(document,{childList:!0,subtree:!0});function a(r){const i={};return r.integrity&&(i.integrity=r.integrity),r.referrerPolicy&&(i.referrerPolicy=r.referrerPolicy),r.crossOrigin==="use-credentials"?i.credentials="include":r.crossOrigin==="anonymous"?i.credentials="omit":i.credentials="same-origin",i}function t(r){if(r.ep)return;r.ep=!0;const i=a(r);fetch(r.href,i)}})();class u extends Error{constructor(a,t){super(t);_(this,"status");this.status=a}}const g="statushub.key";function w(){return sessionStorage.getItem(g)}function C(e){sessionStorage.setItem(g,e)}function k(){sessionStorage.removeItem(g)}async function L(e,n={}){const a=w();if(!a)throw new u(401,"connect with an API key first");const t=await fetch(e,{...n,headers:{Authorization:`Bearer ${a}`,"Content-Type":"application/json",...n.headers??{}}});if(t.status===204)return;if(t.status===401)throw new u(401,"the API key was not accepted");if(t.status===403)throw new u(403,"this key's role is not sufficient for that");const r=await t.json().catch(()=>null);if(!t.ok)throw new u(t.status,(r==null?void 0:r.error)??`${t.status} from ${e}`);return r}const l=e=>L(e),T=(e,n)=>L(e,{method:"POST",body:void 0}),H=e=>l(`/v1/events?${e}`),M=e=>l(`/v1/events/${encodeURIComponent(e)}`),q=e=>T(`/v1/events/${encodeURIComponent(e)}/replay`),x=()=>l("/v1/unknown-statuses"),P=()=>l("/v1/deliveries?status=dead_letter&limit=100"),I=e=>T(`/v1/deliveries/${e}/retry`),R=()=>l("/v1/endpoints"),j=()=>l("/v1/destinations"),O=()=>l("/v1/adapters"),U=()=>l("/v1/listen"),K=()=>l("/v1/audit?limit=100");async function B(){const e=w();if(!e)throw new u(401,"connect with an API key first");const n=await fetch("/v1/audit/verify",{headers:{Authorization:`Bearer ${e}`}});if(n.status===401||n.status===403)throw new u(n.status,"not permitted to verify the audit chain");return await n.json()}const F={NGN:2,USD:2,EUR:2,GBP:2,GHS:2,KES:2,ZAR:2,TZS:2,EGP:2,UGX:0,RWF:0,XOF:0,XAF:0,JPY:0,KRW:0,VND:0,BHD:3,IQD:3,JOD:3,KWD:3,LYD:3,OMR:3,TND:3};function E(e,n){if(!n)return e===0?"—":String(e);const a=F[n]??2,t=e<0,r=String(Math.abs(e)).padStart(a+1,"0"),i=r.slice(0,r.length-a)||"0",d=a>0?"."+r.slice(r.length-a):"",o=Number(i).toLocaleString("en-US");return`${t?"-":""}${o}${d} ${n}`}function h(e){if(!e)return"—";const n=new Date(e);return Number.isNaN(n.getTime())?e:n.toISOString().replace("T"," ").slice(0,19)+"Z"}function G(e){if(!e)return"—";const n=new Date(e);if(Number.isNaN(n.getTime()))return e;const a=(Date.now()-n.getTime())/1e3;return a<60?`${Math.round(a)}s ago`:a<3600?`${Math.round(a/60)}m ago`:a<86400?`${Math.round(a/3600)}h ago`:`${Math.round(a/86400)}d ago`}function W(e){return e==null?"—":e<1e3?`${e}ms`:`${(e/1e3).toFixed(1)}s`}function s(e){return String(e??"").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#39;")}function c(e,n){const a=String(e??"");return a.length>n?a.slice(0,n)+"…":a}function v(e,n){return n.length===0?"":`<table>
    <thead><tr>${e.map(a=>`<th>${s(a)}</th>`).join("")}</tr></thead>
    <tbody>${n.join("")}</tbody>
  </table>`}function m(e){return`<p class="empty">${s(e)}</p>`}function D(e){const n=[e.mapping_complete===!1?'<span class="flag">mapping incomplete</span>':"",e.unmapped_status?`<span class="flag">unmapped: ${s(e.unmapped_status)}</span>`:"",e.redacted?'<span class="flag">redacted</span>':""].join("");return`<span class="status ${s(e.status)}">${s(e.status)}</span>${n}`}const X=async e=>{e.innerHTML=`
    <h2>Events</h2>
    <p class="hint">Every event, in the shape your destination received it. Search by transaction
      reference when a customer asks about one payment; filter on <em>mapping incomplete</em> to
      see what StatusHub could not fully read.</p>
    <form class="filters" id="f">
      <input name="transaction_ref" placeholder="transaction reference" autocomplete="off">
      <input name="provider" placeholder="provider" autocomplete="off">
      <select name="status">
        <option value="">any status</option>
        ${["pending","success","failed","reversed","abandoned","unknown"].map(r=>`<option>${r}</option>`).join("")}
      </select>
      <select name="mapping_complete">
        <option value="">any mapping</option>
        <option value="false">incomplete only</option>
        <option value="true">complete only</option>
      </select>
      <button type="submit">Search</button>
    </form>
    <div id="out" class="empty">searching…</div>`;const n=e.querySelector("#f"),a=e.querySelector("#out"),t=async()=>{const r=new URLSearchParams;for(const[o,f]of new FormData(n).entries())typeof f=="string"&&f.trim()&&r.set(o,f.trim());r.set("limit","100"),a.className="empty",a.textContent="searching…";const d=(await H(r.toString())).events??[];if(d.length===0){a.textContent="no matching events";return}a.className="",a.innerHTML=v(["occurred (UTC)","provider","transaction ref","status","amount","event"],d.map(o=>`<tr data-id="${s(o.event_id)}" class="clickable">
          <td class="mono">${s(h(o.occurred_at))}</td>
          <td>${s(o.provider)}</td>
          <td class="mono">${s(o.transaction_ref)}</td>
          <td>${D(o)}</td>
          <td class="num">${s(E(o.amount_minor,o.currency))}</td>
          <td class="mono">${s(c(o.event_id,30))}</td>
        </tr>`));for(const o of a.querySelectorAll("tr[data-id]"))o.addEventListener("click",()=>{location.hash=`events/${o.dataset.id}`})};n.addEventListener("submit",r=>{r.preventDefault(),t().catch(i=>{a.className="empty",a.textContent=String(i.message??i)})}),await t()};function z(e){return async n=>{const a=await M(e),t=a.event;n.innerHTML=`
      <p><a href="#events">← events</a></p>
      <h2>${s(t.transaction_ref)}</h2>
      <div class="cards">
        <div class="card"><div class="n">${D(t)}</div><div class="l">status</div></div>
        <div class="card"><div class="n">${s(E(t.amount_minor,t.currency))}</div><div class="l">amount</div></div>
        <div class="card"><div class="n">${s(t.provider)}</div><div class="l">provider</div></div>
        <div class="card"><div class="n">${s(a.delivery_count)}</div><div class="l">delivery attempts</div></div>
      </div>

      <h3>Canonical event</h3>
      <p class="hint">This is exactly what your destination received — the same bytes, rendered.</p>
      <pre>${s(JSON.stringify(t,null,2))}</pre>

      <h3>Deliveries</h3>
      ${(a.deliveries??[]).length===0?m("no delivery attempts. Either no destination matched this event, or it has not been queued yet — both are visible under Destinations."):v(["created (UTC)","destination","attempt","status","code","took","response"],a.deliveries.map(r=>`<tr>
                  <td class="mono">${s(h(r.created_at))}</td>
                  <td class="mono">${s(c(r.destination_id,22))}</td>
                  <td class="num">${s(r.attempt)}${r.is_replay?'<span class="flag">replay</span>':""}</td>
                  <td><span class="status ${s(r.status)}">${s(r.status)}</span></td>
                  <td class="num">${s(r.response_code??"—")}</td>
                  <td class="num">${s(W(r.duration_ms))}</td>
                  <td class="mono">${s(c(r.response_body||r.error||"",90))}</td>
                </tr>`))}

      <p><button id="replay">Replay this event</button>
        <span class="hint">Sent again with <code>X-StatusHub-Replay: true</code> and the same
        idempotency key, so a handler that already processed it recognises it.</span></p>
      <p id="replay-out" class="hint"></p>`,n.querySelector("#replay").addEventListener("click",async r=>{const i=r.currentTarget,d=n.querySelector("#replay-out");i.disabled=!0;try{await q(e),d.textContent="queued. It will be delivered within a second or two."}catch(o){d.textContent=`could not replay: ${o.message}`,i.disabled=!1}})}}const J=async e=>{const a=(await x()).unknown_statuses??[];e.innerHTML=`
    <h2>Unknown statuses</h2>
    <p class="hint">Provider status values with no mapping, most frequent first. Events carrying
      them were forwarded as <code>unknown</code> rather than guessed at — mapping an unrecognised
      value to <em>failed</em> is how a fintech reverses a payment that succeeded.</p>
    ${a.length===0?m("nothing unmapped. Every provider value seen recently has a mapping."):v(["provider","value","seen","first","last","sample event"],a.map(t=>`<tr>
                <td>${s(t.provider)}</td>
                <td class="mono">${s(t.raw_value)}</td>
                <td class="num">${s(t.count)}</td>
                <td class="mono">${s(h(t.first_seen))}</td>
                <td class="mono">${s(h(t.last_seen))}</td>
                <td class="mono"><a href="#events/${s(t.sample_event_id)}">${s(c(t.sample_event_id,26))}</a></td>
              </tr>`))}`},Y=async e=>{const a=(await P()).deliveries??[];e.innerHTML=`
    <h2>Dead letters</h2>
    <p class="hint">Deliveries that exhausted their retry budget. Nothing is lost: retrying creates
      a <em>new</em> delivery rather than overwriting this record, because the failure is the
      evidence of what the destination said and when.</p>
    ${a.length===0?m("no dead letters."):v(["created (UTC)","destination","attempts","code","response",""],a.map(t=>`<tr>
                <td class="mono">${s(h(t.created_at))}</td>
                <td class="mono">${s(c(t.destination_id,22))}</td>
                <td class="num">${s(t.attempt)}</td>
                <td class="num">${s(t.response_code??"—")}</td>
                <td class="mono">${s(c(t.response_body||t.error||"",80))}</td>
                <td><button data-retry="${s(t.id)}">Retry</button></td>
              </tr>`))}`;for(const t of e.querySelectorAll("button[data-retry]"))t.addEventListener("click",async()=>{t.disabled=!0,t.textContent="queued",await I(Number(t.dataset.retry))})},Z=async e=>{const a=(await R()).endpoints??[];e.innerHTML=`
    <h2>Endpoints</h2>
    <p class="hint">The URLs you paste into each provider's dashboard. Rotating a token changes only
      the token, not the shape of the URL — so a rotation is a one-line edit on their side.</p>
    ${a.length===0?m("no endpoints yet."):a.map(t=>`<div class="card wide">
                <div><strong>${s(t.provider)}</strong> · ${s(t.environment)} ·
                  adapter ${s(t.adapter)}
                  ${t.enabled?"":'<span class="flag">disabled</span>'}</div>
                <pre>${s(t.receiver_url)}</pre>
                <div class="l">secret reference <code>${s(t.secret_ref)}</code> — StatusHub stores
                  the reference, never the secret</div>
                ${t.warning?`<p class="hint warn"><span class="flag">weaker guarantee</span> ${s(t.warning)}</p>`:""}
              </div>`).join("")}`},V=async e=>{const a=(await j()).destinations??[];e.innerHTML=`
    <h2>Destinations</h2>
    <p class="hint">Where events are forwarded. Each keeps the schema version it was created with:
      a newer version never moves an existing handler on its own.</p>
    ${a.length===0?m("no destinations. Events are still stored and searchable — nothing is being forwarded."):v(["name","url","schema","retry schedule","raw"],a.map(t=>`<tr>
                <td>${s(t.name||"—")}</td>
                <td class="mono">${s(t.url)}</td>
                <td class="mono">${s(t.schema_version)}</td>
                <td class="mono">${s((t.retry_schedule??[]).join(", "))}</td>
                <td>${t.include_raw?"included":""}</td>
              </tr>`))}`},Q=async e=>{const n=await O();e.innerHTML=`
    <h2>Adapters</h2>
    <p class="hint">Each documents its own signature scheme — including where that scheme is weaker
      than the others. Worth reading before relying on one.</p>
    ${n.adapters.map(({built_in:a,description:t})=>t.error?`<div class="card wide">
            <div><strong>${s(t.name)}</strong> <span class="flag">does not load</span></div>
            <div class="l">${s(t.error)}</div></div>`:`<div class="card wide">
          <div><strong>${s(t.display_name||t.name)}</strong>
            ${a?"":'<span class="flag">yours</span>'}
            · amounts in ${s(t.amount_unit)} units
            · ${t.supplies_event_id?"supplies an event ID":"no event ID — dedupes on the body hash"}</div>
          <div class="l">${s(t.signature_scheme)}</div>
          ${t.notes?`<p class="hint">${s(t.notes)}</p>`:""}
        </div>`).join("")}`},ee=async e=>{const a=(await U()).sessions??[];e.innerHTML=`
    <h2>Listening</h2>
    <p class="hint">Developers streaming live events to their own machines with
      <code>statushubctl listen</code>. Events are copied, never diverted — your real destinations
      keep receiving everything. Shown here because a laptop receiving live production payloads is
      something the whole team should be able to see.</p>
    ${a.length===0?m("nobody is listening."):v(["session","forwarding to","started","last seen","delivered","failed"],a.map(t=>`<tr>
                <td class="mono">${s(c(t.id,24))}</td>
                <td class="mono">${s(t.forward||"—")}</td>
                <td class="mono">${s(h(t.started_at))}</td>
                <td class="mono">${s(G(t.last_seen))}</td>
                <td class="num">${s(t.delivered)}</td>
                <td class="num">${s(t.failed)}</td>
              </tr>`))}`},te=async e=>{const[n,a]=await Promise.all([B(),K()]),t=a.records??[],r=n.records===0?{text:"no records",cls:"warn"}:n.intact?{text:"intact",cls:"ok"}:{text:"BROKEN",cls:"bad"};e.innerHTML=`
    <h2>Audit</h2>
    <div class="cards">
      <div class="card"><div class="n ${r.cls}">${s(r.text)}</div><div class="l">hash chain</div></div>
      <div class="card"><div class="n">${s(n.records)}</div><div class="l">records</div></div>
      <div class="card"><div class="n mono small">${s(c(n.head_hash,22))}</div><div class="l">head</div></div>
    </div>
    ${n.records===0?`<div class="banner">An empty chain verifies trivially. That is not the same as an intact
             audit trail, so it is not reported as one.</div>`:""}
    ${!n.intact&&n.records>0?`<div class="banner error">Chain broken at ${s(n.broken_at)}: ${s(n.reason)}.
             This is a security incident — preserve state and escalate. Do not restart anything.</div>`:""}
    <p class="hint">Every state change, hash-chained per tenant. Corrections are appended, never
      applied: a wrong record stays, followed by one that explains it.</p>
    ${t.length===0?m("no records in this window."):v(["recorded (UTC)","event","actor","subject"],t.map(i=>{var d,o,f,b;return`<tr>
                <td class="mono">${s(h(i.recorded_at))}</td>
                <td>${s(i.event_type)}${i.corrects?'<span class="flag">correction</span>':""}</td>
                <td class="mono">${s((d=i.actor)==null?void 0:d.type)}${(o=i.actor)!=null&&o.id?" "+s(c(i.actor.id,20)):""}</td>
                <td class="mono">${s((f=i.subject)==null?void 0:f.type)} ${s(c((b=i.subject)==null?void 0:b.id,26))}</td>
              </tr>`}))}`},$=[{id:"events",label:"Events",view:X},{id:"unknown",label:"Unknown statuses",view:J},{id:"deadletters",label:"Dead letters",view:Y},{id:"endpoints",label:"Endpoints",view:Z},{id:"destinations",label:"Destinations",view:V},{id:"adapters",label:"Adapters",view:Q},{id:"listening",label:"Listening",view:ee},{id:"audit",label:"Audit",view:te}],p=document.querySelector("#app");function ne(){const e=location.hash.slice(1)||"events",[n,a]=[e.split("/")[0],e.split("/").slice(1).join("/")];if(n==="events"&&a)return{tab:"events",view:z(a)};const t=$.find(r=>r.id===n)??$[0];return{tab:t.id,view:t.view}}function se(e){p.innerHTML=`
    <header>
      <h1>StatusHub</h1>
      <nav>${$.map(n=>`<a href="#${n.id}" class="${n.id===e?"on":""}">${s(n.label)}</a>`).join("")}</nav>
      <button id="disconnect" class="quiet">Disconnect</button>
    </header>
    <main id="view"></main>
    <footer><span id="status">connected</span></footer>`,p.querySelector("#disconnect").addEventListener("click",()=>{k(),y()})}function S(e){p.innerHTML=`
    <header><h1>StatusHub</h1></header>
    <main>
      <h2>Connect</h2>
      <p class="hint">Paste an API key. It is held in this tab only — never in localStorage, so
        closing the tab ends the session and a shared machine does not keep it.</p>
      ${e?`<div class="banner error">${s(e)}</div>`:""}
      <form id="connect" class="filters">
        <input id="key" type="password" placeholder="sh_live_… or sh_test_…"
               autocomplete="off" spellcheck="false" size="46">
        <button type="submit">Connect</button>
      </form>
    </main>`,p.querySelector("#connect").addEventListener("submit",a=>{a.preventDefault();const t=p.querySelector("#key").value.trim();t&&(C(t),y())})}async function y(){if(!w()){S();return}const{tab:e,view:n}=ne();se(e);const a=p.querySelector("#view"),t=p.querySelector("#status");a.innerHTML='<p class="empty">loading…</p>';try{await n(a),t.textContent=`connected · ${e}`}catch(r){if(r instanceof u&&r.status===401){k(),S(r.message);return}a.innerHTML=`<div class="banner error">${s(r.message)}</div>`,t.textContent="error"}}window.addEventListener("hashchange",()=>void y());y();
