/** The office's back office. Reads its own records; changes nothing. */
const $ = (id) => document.getElementById(id);

/**
 * Not `escape`: that is a built-in global, the legacy URL encoder, and a
 * page that calls it without defining its own gets %20 where it wanted a
 * space. Shadowing a global to mean something else is the trap; a name of
 * our own is the way out of it.
 */
const esc = (s) => String(s).replace(/[&<>]/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

async function refresh() {
  const keys = await (await fetch('/back-office/keys')).json();
  $('keys').innerHTML =
    `<div class="secret"><h4>never exists outside the signing operation</h4>` +
    `<p>${keys._never_exposed_in_a_deployment}</p></div>` +
    `<table><tbody>` +
    `<tr><td style="width:9rem">k<sub>p</sub><sup>(R)</sup> fingerprint</td>` +
    `<td class="mono">${keys['k_p^(R) fingerprint']}</td></tr>` +
    `<tr><td>its purpose</td><td>${keys['k_p^(R) purpose']}</td></tr>` +
    `<tr><td>k<sub>p</sub><sup>(O)</sup></td><td class="mono">${keys['k_p^(O)']}</td></tr>` +
    `<tr><td>its purpose</td><td>${keys['k_p^(O) purpose']}</td></tr>` +
    `</tbody></table>`;

  // Whether the second route is offered at all, and on whose certificates.
  // An office that is not offering it should say so here rather than only
  // to the voter it turns away -- and should say which directory it read,
  // because anchors in the wrong place and no anchors at all look the same
  // from every other angle.
  const trust = await (await fetch('/back-office/trust')).json();
  const where = esc(trust.looked_in ?? 'nowhere — no directory configured');
  $('trust').innerHTML = trust.offered
    ? `<div class="row"><span class="label">route</span>`
      + `<span class="value same">offered</span></div>`
      + `<div class="row"><span class="label">anchors read from</span>`
      + `<span class="value mono">${where}</span></div>`
      + `<div class="row"><span class="label">pinned on</span>`
      + `<span class="value">${esc(trust.pinned_on || 'not recorded')}</span></div>`
      + `<table style="margin-top:.7rem"><thead><tr><th>subject</th>`
      + `<th>sha-256</th><th>fetched from</th></tr></thead><tbody>`
      + (trust.anchors.length
          ? trust.anchors.map((a) =>
              `<tr><td>${esc(a.subject)}</td>`
              + `<td class="mono">${esc(String(a.sha256).slice(0, 24))}…</td>`
              + `<td class="mono">${esc(a.source)}</td></tr>`).join('')
          : `<tr><td colspan="3" class="muted">the validator records no `
            + `provenance for its anchors</td></tr>`)
      + `</tbody></table>`
    : `<div class="row"><span class="label">route</span>`
      + `<span class="value held">not offered</span></div>`
      + `<div class="row"><span class="label">looked in</span>`
      + `<span class="value mono">${where}</span></div>`
      + `<p class="prose" style="margin:.6rem 0 0">${esc(trust.why)}</p>`;

  const held = await (await fetch('/back-office/pending')).json();
  $('manual').checked = held.manual_release;
  $('pending').innerHTML = held.pending.length
    ? held.pending.map((r) =>
        `<tr><td class="mono">${r.voter_id}</td><td class="mono">${r.blinded_key}</td>` +
        `<td><button data-release="${r.voter_id}">Sign and release</button> ` +
        `<button data-cancel="${r.voter_id}">Cancel</button></td></tr>`).join('')
    : `<tr><td colspan="3" class="muted">${held.manual_release
        ? 'nothing held' : 'signing at once — nothing is held'}</td></tr>`;
  for (const b of document.querySelectorAll('[data-release]')) {
    b.onclick = async () => {
      b.disabled = true;
      await fetch('/back-office/release', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ voter_id: b.dataset.release }) });
      refresh();
    };
  }
  for (const b of document.querySelectorAll('[data-cancel]')) {
    b.onclick = async () => {
      b.disabled = true;
      await fetch('/back-office/cancel', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ voter_id: b.dataset.cancel }) });
      refresh();
    };
  }

  const audit = await (await fetch('/back-office/audit')).json();
  $('audit').innerHTML = audit.entries.length
    ? audit.entries.map((e) =>
        `<tr><td class="mono">${e.voter_id}</td>` +
        `<td class="${e.reason_withheld ? 'held' : ''}">${e.recorded}</td>` +
        `<td class="${e.reason_withheld ? 'held' : 'same'}">${e.disclosed}` +
        `${e.reason_withheld ? ' — reason withheld' : ''}</td></tr>`).join('')
    : '<tr><td colspan="3" class="muted">no requests yet</td></tr>';

  const log = await (await fetch('/release-log')).json();
  $('reg-count').textContent = `${log.count} ${log.count === 1 ? 'token' : 'tokens'}`;
  $('reg-head').textContent = `${String(log.head).slice(0, 24)}…`;
  // One row per release, and nothing but the commitment in it. The office
  // holds the identifier behind each of these and does not put it here:
  // this is the published register, and its whole point is that reading it
  // tells you how many tokens exist and nothing about whose they are.
  $('register').innerHTML = log.entries.length
    ? log.entries.map((e, i) => `<tr><td class="mono">${e.index ?? i}</td>`
        + `<td class="mono">${esc(String(e.commitment ?? (e.payload || {}).commitment))}</td></tr>`).join('')
    : '<tr><td colspan="2" class="muted">no token released yet</td></tr>';

  $('asof').textContent = `as of ${new Date().toLocaleTimeString()}`;
}

$('manual').onchange = async () => {
  await fetch('/back-office/mode', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ manual: $('manual').checked }) });
  refresh();
};

$('refresh').onclick = () => refresh();
refresh().catch((err) => { $('asof').textContent = `failed: ${err}`; });
