/** The ballot box's operator console. Reads the registry; closes the poll. */
const $ = (id) => document.getElementById(id);

const escape = (s) => String(s).replace(/[&<>]/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

// Both figures come from the box, but while the poll is open they do not come
// from the same moment: the submissions are counted live from the published
// commitments, whereas the ballots that will count are known only as of the
// last published report. The page says which is which rather than presenting
// a pair that invites subtraction.
function showWillCount(value, note) {
  $('voters').textContent = value;
  $('voters-note').textContent = note;
}

function showReports(reports) {
  if (!reports.length) {
    $('reports').innerHTML =
      '<tr><td colspan="4">no report published yet — the first boundary of '
      + 'the configured interval has not passed</td></tr>';
    return;
  }
  $('reports').innerHTML = reports.map((r) => `<tr>
      <td class="mono">${escape(r.at)}</td>
      <td>${r.after_accepted}</td>
      <td>${r.voters}</td>
      <td class="mono">${escape(JSON.stringify(r.counts))}</td>
    </tr>`).join('');
}

async function refresh() {
  const view = await (await fetch('/published')).json();
  const open = !('records' in view);
  const accepted = open ? view.commitments.accepted : view.records.accepted;
  const rejected = open ? view.commitments.rejected : view.records.rejected;
  const reports = view.running_tally || [];

  $('state').innerHTML = open
    ? '<span class="ok">open</span> — records withheld, commitments published'
    : '<span class="warn">closed</span> — every record released in clear';
  $('accepted').textContent = accepted.length;
  $('rejected').textContent = rejected.length;
  $('head').textContent = view.heads.accepted;
  $('close').disabled = !open;
  $('close-note').textContent = open ? '' : 'already closed; this cannot be undone';

  showReports(reports);

  if (!open) {
    const t = await (await fetch('/tally')).json();
    showWillCount(t.voters, 'final');
    $('tally').innerHTML = `<pre>${escape(JSON.stringify(t, null, 2))}</pre>`;
  } else {
    const latest = reports.length ? reports[reports.length - 1] : null;
    showWillCount(latest ? latest.voters : '—',
                  latest ? `as published at ${latest.at}`
                         : 'not published yet; not knowable from here either');
    $('tally').textContent = 'not until the poll closes';
  }
  $('asof').textContent = `as of ${new Date().toLocaleTimeString()}`;
}

$('close').onclick = async () => {
  if (!confirm('Close the poll? Submissions stop and every record is '
             + 'released in clear. This cannot be undone.')) return;
  $('close').disabled = true;
  await fetch('/close', { method: 'POST' });
  refresh();
};

$('refresh').onclick = () => refresh();
refresh().catch((err) => { $('asof').textContent = `failed: ${err}`; });
