/** The office's back office. Reads its own records; changes nothing. */
const $ = (id) => document.getElementById(id);

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

  const held = await (await fetch('/back-office/pending')).json();
  $('manual').checked = held.manual_release;
  $('pending').innerHTML = held.pending.length
    ? held.pending.map((r) =>
        `<tr><td class="mono">${r.voter_id}</td><td class="mono">${r.blinded_key}</td>` +
        `<td><button data-release="${r.voter_id}">Sign and release</button> ` +
        `<button data-cancel="${r.voter_id}">Cancel</button></td></tr>`).join('')
    : `<tr><td colspan="3" style="color:#888">${held.manual_release
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
    : '<tr><td colspan="3" style="color:#888">no requests yet</td></tr>';

  const log = await (await fetch('/release-log')).json();
  $('register').innerHTML =
    `${log.count} released · head ${log.head}` +
    (log.entries.length ? `<pre>${JSON.stringify(log.entries, null, 2)}</pre>` : '');

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
