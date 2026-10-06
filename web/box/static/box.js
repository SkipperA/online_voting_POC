/** The ballot box's operator console. Reads the registry; closes the poll. */
const $ = (id) => document.getElementById(id);

async function refresh() {
  const view = await (await fetch('/published')).json();
  const open = !('records' in view);
  const accepted = open ? view.commitments.accepted : view.records.accepted;
  const rejected = open ? view.commitments.rejected : view.records.rejected;

  $('state').innerHTML = open
    ? '<span class="ok">open</span> — records withheld, commitments published'
    : '<span class="warn">closed</span> — every record released in clear';
  $('accepted').textContent = accepted.length;
  $('rejected').textContent = rejected.length;
  $('head').textContent = view.heads.accepted;
  $('close').disabled = !open;
  $('close-note').textContent = open ? '' : 'already closed; this cannot be undone';

  if (open) {
    $('tally').textContent = 'not until the poll closes';
  } else {
    const t = await (await fetch('/tally')).json();
    $('tally').innerHTML =
      `<pre>${JSON.stringify(t, null, 2)}</pre>`;
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
