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

$('refresh').onclick = () => refresh();
refresh().catch((err) => { $('asof').textContent = `failed: ${err}`; });
