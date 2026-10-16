/** The ballot box's operator console. Reads the registry; closes the poll. */
const $ = (id) => document.getElementById(id);

/**
 * Not `escape`: that is a built-in global, the legacy URL encoder, and a
 * page that calls it without defining its own gets %20 where it wanted a
 * space. Shadowing a global to mean something else is the trap; a name of
 * our own is the way out of it.
 */
const esc = (s) => String(s).replace(/[&<>]/g,
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

// The shared series palette. Defined in tokens.css and used identically by
// the checker, so a colour means the same thing on both pages. Protest
// selections are grey on purpose: an out-of-range value is not a candidate
// and must never be dressed as one.
const SERIES = (option) => `var(--series-${((option - 1) % 6) + 1})`;
const PROTEST = 'var(--series-protest)';

/** The bands of one report or tally: every option, then protest if any. */
function bands(figures) {
  const counts = figures.counts || {};
  const out = Object.keys(counts)
    .map(Number).sort((a, b) => a - b)
    .map((option) => ({ label: `option ${option}`, colour: SERIES(option),
                        value: counts[option] }));
  const protest = Object.values(figures.protest_codes || {})
    .reduce((a, b) => a + b, 0);
  if (protest) out.push({ label: 'outside the list', colour: PROTEST, value: protest });
  return out;
}

/** A report's figures as proportions of itself, with the numbers kept. */
function spark(figures) {
  const parts = bands(figures);
  const total = parts.reduce((a, b) => a + b.value, 0);
  if (!total) return '<span class="muted">nothing counted in this report</span>';
  const segments = parts.filter((p) => p.value).map((p) =>
    `<i style="width:${(p.value / total) * 100}%;background:${p.colour}"`
    + ` title="${esc(p.label)}: ${p.value}"></i>`).join('');
  const numbers = parts.map((p) => p.value).join(' · ');
  return `<div class="spark">${segments}</div>`
    + `<span class="muted" style="font-size:var(--t-sm)">${numbers}</span>`;
}

function legend(target, figures) {
  $(target).innerHTML = bands(figures).map((p) =>
    `<span><i class="swatch" style="background:${p.colour}"></i>${esc(p.label)}</span>`
  ).join('');
}

/** The tally as rows rather than as the JSON it arrived in. */
function showTally(t) {
  const parts = bands(t);
  const top = Math.max(1, ...parts.map((p) => p.value));
  const rows = parts.map((p) => `<div class="tally-row">
      <span>${esc(p.label)}</span>
      <span class="tally-bar"><i style="width:${(p.value / top) * 100}%;
        background:${p.colour}"></i></span>
      <span class="tally-n">${p.value}</span>
    </div>`).join('');
  // Every out-of-range value kept apart, because merging them is precisely
  // what requirement 7 does not permit.
  const codes = Object.entries(t.protest_codes || {});
  const protest = codes.length
    ? `<p class="sub" style="margin:.7rem 0 0">Outside the list, by value: `
      + codes.map(([v, n]) => `<code>${esc(v)}</code> × ${n}`).join(', ') + '</p>'
    : '';
  $('tally').innerHTML = rows + `<p class="figures">
      <span><span class="muted">ballots counted</span> ${t.voters}</span>
      <span><span class="muted">valid</span> ${t.valid}</span>
      <span><span class="muted">invalid</span> ${t.invalid}</span>
      <span><span class="muted">rejected, published and not counted</span> ${t.rejected}</span>
    </p>` + protest
    + `<p class="sub" style="margin:.5rem 0 0">Chain head
       <code>${esc((t.ledger_head || '').slice(0, 16))}…</code> — every figure
       above is recomputable from the released records by anyone.</p>`;
  legend('reports-legend', t);
}

function showReports(reports) {
  if (!reports.length) {
    $('reports').innerHTML =
      '<tr><td colspan="4">no report published yet — the first boundary of '
      + 'the configured interval has not passed</td></tr>';
    return;
  }
  $('reports').innerHTML = reports.map((r) => `<tr>
      <td class="mono">${esc((r.at || '').slice(11, 19))}</td>
      <td>${r.after_accepted}</td>
      <td>${r.voters}</td>
      <td>${spark(r)}</td>
    </tr>`).join('');
  legend('reports-legend', reports[reports.length - 1]);
}

async function refresh() {
  const view = await (await fetch('/published')).json();
  const open = !('records' in view);
  const accepted = open ? view.commitments.accepted : view.records.accepted;
  const rejected = open ? view.commitments.rejected : view.records.rejected;
  const reports = view.running_tally || [];

  const acts = (view.acts || []).map((a) =>
    `${a.phase} at ${new Date(a.at * 1000).toLocaleTimeString()}`).join(', ');
  $('state').innerHTML = (view.phase === 'not opened'
    ? '<span class="warn">not opened</span> — submissions are refused; nothing is recorded'
    : open
      ? '<span class="ok">open</span> — records withheld, commitments published'
      : '<span class="warn">closed</span> — every record released in clear')
    + (acts ? ` <span class="muted">(${acts})</span>` : '');
  $('accepted').textContent = accepted.length;
  $('rejected').textContent = rejected.length;
  $('head').textContent = view.heads.accepted;
  // Three states: a box nobody opened is not a box that has shut.
  const notYet = view.phase === 'not opened';
  $('open').disabled = !notYet;
  $('close').disabled = notYet || !open;
  $('get-ledger').disabled = open;
  $('ledger-note').textContent = open
    ? 'the registry is released in clear at the close'
    : 'one canonical file; check it somewhere this origin does not control';
  $('close-note').textContent = open ? '' : 'already closed; this cannot be undone';

  showReports(reports);

  if (!open) {
    const t = await (await fetch('/tally')).json();
    showWillCount(t.voters, 'final');
    showTally(t);
  } else {
    const latest = reports.length ? reports[reports.length - 1] : null;
    showWillCount(latest ? latest.voters : '—',
                  latest ? `as published at ${latest.at}`
                         : 'not published yet; not knowable from here either');
    $('tally').innerHTML = '<p class="muted">Not until the poll closes. The '
      + 'reports above are what is knowable before then — by the operator as '
      + 'much as by anybody else.</p>';
  }
  $('asof').textContent = `as of ${new Date().toLocaleTimeString()}`;
}

$('open').onclick = async () => {
  const response = await fetch('/open', { method: 'POST' });
  if (!response.ok) { $('close-note').textContent = (await response.json()).detail; return; }
  refresh();
};

$('close').onclick = async () => {
  if (!confirm('Close the poll? Submissions stop and every record is '
             + 'released in clear. This cannot be undone.')) return;
  $('close').disabled = true;
  await fetch('/close', { method: 'POST' });
  refresh();
};

$('get-ledger').onclick = () => { window.location = '/ledger'; };

$('refresh').onclick = () => refresh();
refresh().catch((err) => { $('asof').textContent = `failed: ${err}`; });
