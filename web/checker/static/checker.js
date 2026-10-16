/** The checker. Reads published artefacts; holds nothing, signs nothing. */
const VRO = document.body.dataset.vroOrigin;
const EBB = document.body.dataset.ebbOrigin;
const CONFIG = document.body.dataset.configOrigin;
const $ = (id) => document.getElementById(id);
const show = (id, text, cls) => { const e = $(id); e.textContent = text; e.className = `value ${cls || ''}`; };

/**
 * Not `escape`: that is a built-in global, the legacy URL encoder, and a
 * page that calls it without defining its own gets %20 where it wanted a
 * space. Shadowing a global to mean something else is the trap; a name of
 * our own is the way out of it.
 */
const esc = (s) => String(s).replace(/[&<>]/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

const stamp = () => new Date().toLocaleTimeString();

// The published election configuration, read once and held. Every signature
// checked on this page is checked against a key from here -- not against a
// key the signer handed over with its own signature, which would verify
// everything and establish nothing.
let PINNED = null;

const unb64 = (t) => Uint8Array.from(
  atob(t.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const b64 = (bytes) => btoa(String.fromCharCode(...bytes))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// ---------------------------------------------------------------------------
// The published figures
//
// Everything here comes from `/published` on the box and the release count on
// the office. Nothing is computed from a privileged feed, and nothing is
// inferred: before the first publication boundary there are no figures, and
// the page says when the next one falls rather than drawing a line through
// points it does not have. The box applies supersession when it counts, so a
// recast ballot moves a series down and the chart has nothing to correct.
// ---------------------------------------------------------------------------
const SERIES = (i) => `var(--series-${(i % 6) + 1})`;
const PROTEST = 'var(--series-protest)';
const svgNS = 'http://www.w3.org/2000/svg';

const el = (name, attrs, text) => {
  const node = document.createElementNS(svgNS, name);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  if (text !== undefined) node.textContent = text;
  return node;
};

/** The series a snapshot list contains: each option, then protest if cast. */
function seriesOf(snapshots, numChoices) {
  const out = [];
  for (let i = 1; i <= numChoices; i += 1) {
    out.push({
      label: `option ${i}`,
      colour: SERIES(i - 1),
      points: snapshots.map((s) => (s.counts || {})[i] || 0),
    });
  }
  const protest = snapshots.map(
    (s) => Object.values(s.protest_codes || {}).reduce((a, b) => a + b, 0));
  if (protest.some((n) => n > 0)) {
    out.push({ label: 'outside the list', colour: PROTEST, points: protest });
  }
  return out;
}

function stepChart(snapshots, numChoices) {
  const W = 680, H = 260, L = 42, R = 14, T = 14, B = 34;
  const series = seriesOf(snapshots, numChoices);
  const top = Math.max(1, ...series.flatMap((s) => s.points));
  const n = snapshots.length;
  const x = (i) => L + (n === 1 ? (W - L - R) / 2 : (i * (W - L - R)) / (n - 1));
  const y = (v) => H - B - (v / top) * (H - T - B);

  const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img',
                          'aria-label': 'ballots per option at each publication boundary' });
  // Axes, and a gridline per whole ballot while the numbers are small.
  const stepY = Math.max(1, Math.ceil(top / 5));
  for (let v = 0; v <= top; v += stepY) {
    svg.appendChild(el('line', { x1: L, x2: W - R, y1: y(v), y2: y(v),
                                 stroke: 'var(--rule)', 'stroke-width': 1 }));
    svg.appendChild(el('text', { x: L - 8, y: y(v) + 4, 'text-anchor': 'end',
                                 fill: 'var(--muted)', 'font-size': 11 }, String(v)));
  }
  svg.appendChild(el('line', { x1: L, x2: L, y1: T, y2: H - B,
                               stroke: 'var(--rule-strong)', 'stroke-width': 1 }));
  // Boundary labels: the first, the last, and the middle one if they fit.
  const marks = n <= 2 ? [...snapshots.keys()] : [0, Math.floor((n - 1) / 2), n - 1];
  for (const i of new Set(marks)) {
    svg.appendChild(el('text', { x: x(i), y: H - 12, 'text-anchor': 'middle',
                                 fill: 'var(--muted)', 'font-size': 11 },
                       (snapshots[i].at || '').slice(11, 19)));
  }
  // The series themselves, drawn as steps: a figure holds until the next
  // boundary republishes it, which is what the publication schedule means.
  for (const s of series) {
    let d = '';
    s.points.forEach((v, i) => {
      d += i === 0 ? `M ${x(i)} ${y(v)}` : ` L ${x(i)} ${y(s.points[i - 1])} L ${x(i)} ${y(v)}`;
    });
    svg.appendChild(el('path', { d, fill: 'none', stroke: s.colour,
                                 'stroke-width': 2, 'stroke-linejoin': 'round' }));
    s.points.forEach((v, i) => svg.appendChild(
      el('circle', { cx: x(i), cy: y(v), r: 2.5, fill: s.colour })));
  }
  return { svg, series };
}

function pieChart(snapshot, numChoices) {
  const series = seriesOf([snapshot], numChoices)
    .map((s) => ({ ...s, value: s.points[0] }))
    .filter((s) => s.value > 0);
  const total = series.reduce((a, s) => a + s.value, 0);
  const S = 220, r = 92, c = S / 2;
  const svg = el('svg', { viewBox: `0 0 ${S} ${S}`, role: 'img',
                          'aria-label': 'the published result so far' });
  if (!total) {
    svg.appendChild(el('circle', { cx: c, cy: c, r, fill: 'none',
                                   stroke: 'var(--rule)', 'stroke-width': 1 }));
    svg.appendChild(el('text', { x: c, y: c + 4, 'text-anchor': 'middle',
                                 fill: 'var(--muted)', 'font-size': 12 },
                       'no ballots counted yet'));
    return { svg, series };
  }
  let angle = -Math.PI / 2;
  for (const s of series) {
    const sweep = (s.value / total) * 2 * Math.PI;
    const [x1, y1] = [c + r * Math.cos(angle), c + r * Math.sin(angle)];
    angle += sweep;
    const [x2, y2] = [c + r * Math.cos(angle), c + r * Math.sin(angle)];
    const d = series.length === 1
      ? `M ${c} ${c - r} A ${r} ${r} 0 1 1 ${c - 0.01} ${c - r} Z`
      : `M ${c} ${c} L ${x1} ${y1} A ${r} ${r} 0 ${sweep > Math.PI ? 1 : 0} 1 ${x2} ${y2} Z`;
    svg.appendChild(el('path', { d, fill: s.colour,
                                 stroke: 'var(--bg)', 'stroke-width': 1.5 }));
  }
  return { svg, series };
}

function legend(series, totals) {
  const box = document.createElement('p');
  box.className = 'legend';
  series.forEach((s, i) => {
    const item = document.createElement('span');
    const swatch = document.createElement('i');
    swatch.className = 'swatch';
    swatch.style.setProperty('--row-hue', s.colour);
    item.appendChild(swatch);
    item.appendChild(document.createTextNode(
      totals ? `${s.label} — ${totals[i]}` : s.label));
    box.appendChild(item);
  });
  return box;
}

/** Seconds until the next publication boundary, or null if there is none. */
function nextBoundary(view, interval) {
  if (!interval) return null;
  const last = view.running_tally.length
    ? view.running_tally[view.running_tally.length - 1].at
    : (view.acts.find((a) => a.phase === 'opened') || {}).at;
  if (!last) return null;
  const from = typeof last === 'number' ? last * 1000 : Date.parse(last);
  return (from + interval * 1000 - Date.now()) / 1000;
}

async function figures() {
  const config = await pinned();
  let view;
  try {
    view = await (await fetch(`${EBB}/published`)).json();
  } catch { return; }
  let released = '—';
  try {
    released = String((await (await fetch(`${VRO}/releases`)).json()).count);
  } catch { /* the office is the office's to answer for */ }

  const interval = config.tally_interval_seconds;
  const snapshots = view.running_tally || [];
  $('fig-election').textContent = config.election_id;
  $('fig-cadence').textContent = interval
    ? `every ${interval}s, and at the close` : 'the close only';
  $('fig-tokens').textContent = released;
  $('fig-entries').textContent = String(view.counts ? view.counts.accepted : 0);

  if (!snapshots.length) {
    $('figures-charts').hidden = true;
    $('figures-waiting').hidden = false;
    const left = nextBoundary(view, interval);
    if (view.phase !== 'open') {
      $('fig-next').textContent = view.phase === 'closed'
        ? 'The poll is closed and published no interim figures: this election '
          + 'chose the close as its only publication point.'
        : 'The poll has not opened. Nothing is published before it does.';
      $('fig-bar').style.width = '0%';
    } else if (left === null) {
      $('fig-next').textContent = 'No interim figures: this election publishes '
        + 'at the close only, which is a choice the administering body makes '
        + 'and a small electorate has reason to make.';
      $('fig-bar').style.width = '0%';
    } else {
      $('fig-next').textContent = `First figures in ${Math.max(0, Math.ceil(left))}s. `
        + 'Until a boundary falls there is no tally to be had — for anyone, '
        + 'the operator included.';
      $('fig-bar').style.width = `${Math.min(100, Math.max(0, (1 - left / interval) * 100))}%`;
    }
    return;
  }

  $('figures-waiting').hidden = false;
  $('figures-charts').hidden = false;
  const left = nextBoundary(view, interval);
  $('fig-next').textContent = view.phase === 'closed'
    ? 'Final figures. The records are open; every number here is recomputable '
      + 'from them.'
    : `Next figures in ${Math.max(0, Math.ceil(left || 0))}s.`;
  $('fig-bar').style.width = view.phase === 'closed' ? '100%'
    : `${Math.min(100, Math.max(0, (1 - (left || 0) / interval) * 100))}%`;

  const last = snapshots[snapshots.length - 1];
  const step = stepChart(snapshots, config.num_choices);
  $('fig-step').replaceChildren(step.svg, legend(step.series));
  $('fig-step-caption').textContent =
    `${snapshots.length} publication ${snapshots.length === 1 ? 'point' : 'points'}, `
    + `from the box's own running tally. Steps, not a curve: a figure holds `
    + `until the next boundary republishes it.`;

  const pie = pieChart(last, config.num_choices);
  $('fig-pie').replaceChildren(pie.svg, legend(pie.series, pie.series.map((s) => s.value)));
  $('fig-pie-caption').textContent = view.phase === 'closed'
    ? `The final count, as published at ${(last.at || '').slice(11, 19)}.`
    : `The count as published at ${(last.at || '').slice(11, 19)} — not the `
      + `live count, which nobody has.`;
}

async function pinned() {
  if (!PINNED) PINNED = await (await fetch(`${CONFIG}/election.json`)).json();
  return PINNED;
}

/** Ed25519 over the canonical SHA-256 digest of the statement. */
async function verifyStatement(publicKeyB64, statement, signatureB64) {
  const key = await crypto.subtle.importKey(
    'raw', unb64(publicKeyB64), { name: 'Ed25519' }, false, ['verify']);
  const canonical = new TextEncoder().encode(JSON.stringify(statement));
  const payload = new Uint8Array(await crypto.subtle.digest('SHA-256', canonical));
  return crypto.subtle.verify({ name: 'Ed25519' }, key, unb64(signatureB64), payload);
}

async function refresh() {
  $('asof').textContent = 'reading…';
  const log = await (await fetch(`${VRO}/release-log`)).json();
  show('released', String(log.count));
  show('vro-head', log.head);

  const view = await (await fetch(`${EBB}/published`)).json();
  const open = !('records' in view);
  const accepted = open ? view.commitments.accepted : view.records.accepted;
  const rejected = open ? view.commitments.rejected : view.records.rejected;
  show('accepted', String(accepted.length));
  show('rejected', String(rejected.length));
  show('ebb-head', view.heads.accepted);

  // The count audit, correctly stated.
  //
  // §3.5 says the number of accepted *entries* must not exceed the number of
  // tokens released. That is false whenever anybody re-votes, which the
  // design explicitly permits: one token certifies one ad-hoc key, and a
  // voter may cast under it as often as they like. The bound that actually
  // holds is over *distinct keys*, not entries.
  //
  // And distinct keys are not visible while voting is open, because the
  // records are withheld. So this check is simply unavailable before the
  // close — stating it as a violation, as it did, reported the design's own
  // re-voting as fraud.
  if (open) {
    show('count-audit',
         `${log.count} tokens released · ${accepted.length} accepted entries ` +
         '(entries may exceed tokens: a voter may re-cast under one token)',
         'muted');
  }
  show('records', open
    ? 'withheld while voting is open — commitments only'
    : `${accepted.length} released in clear`, open ? 'muted' : 'ok');

  // Both of these need the ledger, which does not exist until the close:
  // the records are withheld while voting is open (§3.5), so the endpoint
  // answers 409 and a button wired to it navigates to an error nobody sees.
  // Disabled with the reason stated, rather than live and inert.
  $('get-ledger').disabled = open;
  $('check-live').disabled = open;
  show('when', open
    ? 'the ledger is released in clear at the close; until then there is '
      + 'nothing to download and nothing to recount'
    : 'the records are out — every check below is available', open ? 'muted' : 'ok');

  if (open) {
    $('asof').textContent = `as of ${stamp()}`;
    show('status', 'Voting is open. Contents are withheld; the chain is not.');
    return;
  }

  // Now that the records are open, the bound that holds can be checked:
  // distinct ad-hoc keys against tokens released. One token, one key, any
  // number of ballots under it.
  const keys = new Set(accepted.map((r) => r.adhoc_public_key));
  const within = keys.size <= log.count;
  show('count-audit',
       `${keys.size} distinct ad-hoc keys \u2264 ${log.count} tokens released — ` +
       `${within ? 'holds' : 'VIOLATED'}`, within ? 'ok' : 'warn');

  $('asof').textContent = `as of ${stamp()}`;
  show('status', 'Poll closed. Run the full check below: the recount this page '
     + 'used to do here verified no tokens and no signatures.');
}

let CREDENTIALS = null;

// Downloads rather than fetches: the file has to leave this origin to be
// worth anything. A verdict computed here is a verdict from a page the
// audited parties serve.
/**
 * The whole check, fed either way.
 *
 * One implementation, run on the server by `tools/verify_election.py` --
 * the same program the button below hands out. A second implementation in
 * this page would be a second thing to get right, and could disagree with
 * the first without anyone noticing.
 */
const LABEL = {
  election: 'election configuration',
  ledger: 'ballot box ledger',
  releases: 'release register',
};

const files = { election: null, ledger: null, releases: null };

function kindOf(parsed) {
  const format = String(parsed.format || '');
  if (format.startsWith('ovpoc-ledger')) return 'ledger';
  if (format.startsWith('ovpoc-releases')) return 'releases';
  if (format.startsWith('ovpoc-supervision')) return 'supervision';
  if ('vro_token_key_spki' in parsed) return 'election';
  return null;
}

function note(key, text, cls) {
  const e = $(`have-${key}`);
  e.textContent = text;
  e.className = `value ${cls || 'muted'}`;
}

function loadFile(inputId, slot) {
  $(inputId).onchange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    // Kept verbatim: the configuration digest is over the bytes that were
    // published, so a file through a parser and back is a different file.
    const text = await file.text();
    let parsed;
    try { parsed = JSON.parse(text); } catch {
      files[slot] = null; note(slot, `${file.name} is not JSON`, 'warn');
      $('check-files').disabled = true; return;
    }
    const kind = kindOf(parsed);
    if (kind === 'supervision') {
      files[slot] = null;
      note(slot, 'that is the supervision register — it names citizens and is '
         + 'not part of this check', 'warn');
    } else if (kind && kind !== slot) {
      files[slot] = null; note(slot, `that is the ${LABEL[kind]}`, 'warn');
    } else if (!kind) {
      files[slot] = null; note(slot, `${file.name} is not one of these`, 'warn');
    } else {
      files[slot] = text; note(slot, file.name, 'ok');
    }
    $('check-files').disabled = !(files.election && files.ledger && files.releases);
  };
}

loadFile('f-election', 'election');
loadFile('f-ledger', 'ledger');
loadFile('f-releases', 'releases');

function render(report) {
  let group = null;
  const rows = report.checks.map((c) => {
    const heading = c.section !== group
      ? `<div class="group">${esc(c.section)}</div>` : '';
    group = c.section;
    return `${heading}<div class="check">
      <span class="verdict ${c.ok ? 'ok' : 'warn'}">${c.ok ? 'pass' : 'FAIL'}</span>
      <span>${esc(c.description)}${
        c.detail ? `<br><span class="detail">${esc(c.detail)}</span>` : ''}</span>
    </div>`;
  });
  $('checks').innerHTML = rows.join('');

  const t = report.tally;
  const options = Object.entries(t.options)
    .map(([k, n]) => `<div class="row"><span class="label">option ${esc(k)}</span><span class="value">${n}</span></div>`);
  const protest = Object.entries(t.outside_the_list)
    .map(([k, n]) => `<div class="row"><span class="label">outside the list: ${esc(k)}</span><span class="value">${n}</span></div>`);
  $('recount').innerHTML = `
    <div class="row"><span class="label">election</span><span class="value">${esc(t.election_id)}</span></div>
    <div class="row"><span class="label">configuration</span><span class="value">${esc(t.configuration_digest)}</span></div>
    ${options.join('')}${protest.join('')}
    <div class="row"><span class="label">ballots accepted</span><span class="value">${t.ballots} from ${t.voters} voters</span></div>
    <div class="row"><span class="label">rejected, published</span><span class="value">${t.rejected}</span></div>`;

  $('status').textContent = report.ok
    ? 'Every check passed. This result follows from the records in these files.'
    : `${report.checks.filter((c) => !c.ok).length} check(s) failed — the result above does not follow.`;
  $('status').className = report.ok ? 'ok' : 'warn';
}


async function check(three) {
  show('verdict', 'checking…', '');
  const response = await fetch('/check', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(three),
  });
  if (!response.ok) {
    show('verdict', (await response.json()).detail, 'warn');
    return;
  }
  render(await response.json());
  $('check-asof').textContent = `checked at ${stamp()}`;
}

$('check-files').onclick = () => check(files)
  .catch((err) => show('verdict', `could not check: ${err}`, 'warn'));

// The convenient path: fetch what the parties published, then check it. The
// page says what that is worth — the files came from the audited parties a
// moment ago, over a connection to a page they serve.
$('check-live').onclick = async () => {
  try {
    const [election, ledger, releases] = await Promise.all([
      (await fetch(`${CONFIG}/election.json`)).text(),
      (await fetch(`${EBB}/ledger`)).text(),
      (await fetch(`${VRO}/releases`)).text(),
    ]);
    await check({ election, ledger, releases });
  } catch (err) {
    show('verdict', `could not read the artefacts: ${err}`, 'warn');
  }
};

$('recheck-state').onclick = () => { refresh(); showPollState(EBB); };

$('get-script').onclick = () => { window.location = '/verify_election.py'; };

$('get-ledger').onclick = () => { window.location = `${EBB}/ledger`; };
$('get-releases').onclick = () => { window.location = `${VRO}/releases`; };

// The configuration is served to be *read* -- it is the one inert, publicly
// pinned artefact, and giving it a download disposition would make it
// awkward to look at. So it is saved here instead, byte for byte: the
// published digest is over exactly those bytes, and a copy retyped out of a
// browser window is a different file even when it looks identical.
$('get-config').onclick = async () => {
  const response = await fetch(`${CONFIG}/election.json`);
  const bytes = await response.clone().blob();
  const { election_id: election } = await response.json();
  const url = URL.createObjectURL(bytes);
  const link = document.createElement('a');
  link.href = url;
  link.download = `Election_config_${election}.json`;
  link.click();
  URL.revokeObjectURL(url);
};


/**
 * The ballot box's phase, from its own published acts rather than from a
 * time the configuration declared. Every party's page shows it, because
 * every party's page means something different depending on it.
 */
async function showPollState(ebbOrigin) {
  const target = document.getElementById('poll-state');
  if (!target) return;
  try {
    const view = await (await fetch(`${ebbOrigin}/published`)).json();
    const when = (phase) => {
      const act = (view.acts || []).find((a) => a.phase === phase);
      return act ? new Date(act.at * 1000).toLocaleString() : null;
    };
    const opened = when('opened');
    const closed = when('closed');
    if (view.phase === 'not opened') {
      target.innerHTML = '<b>Ballot box: not opened.</b> Submissions are '
        + 'refused and nothing is recorded.';
    } else if (view.phase === 'open') {
      target.innerHTML = `<b>Ballot box: open</b> since ${opened}. `
        + 'Ballot contents are withheld until the close.';
    } else {
      target.innerHTML = `<b>Ballot box: closed</b> at ${closed} `
        + `(opened ${opened}). Every record is released in clear.`;
    }
  } catch (err) {
    target.textContent = `Ballot box: could not be read (${err}).`;
  }
}

showPollState(EBB);
figures();
// The figures move on the election's schedule, so the page follows it rather
// than waiting to be asked. One second, because the progress bar counts down
// in seconds; the request is two small reads of published artefacts.
setInterval(figures, 1000);

$('refresh').onclick = () => { refresh(); showPollState(EBB); figures(); };
$('d1-again').onclick = () => CREDENTIALS && ask(CREDENTIALS);

$('query').onchange = async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  try { CREDENTIALS = JSON.parse(await file.text()); }
  catch { show('d1', 'That file is not a release query.', 'warn'); return; }
  $('d1-again').disabled = false;
  await ask(CREDENTIALS);
};

/**
 * D1, asked now.
 *
 * The answer describes the register at the instant of asking and at no
 * other. A negative answer left on screen after a token has been released
 * is not merely stale: it displays, as current, the very claim the check
 * exists to make. Hence the timestamp and the Ask again control.
 */
async function ask(credentials) {
  const answer = await (await fetch(`${VRO}/release-queries`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(credentials),
  })).json();

  if (answer.released) {
    // An affirmative answer needs no signature: it hands over the value that
    // opens this voter's own commitment in the published register, so the
    // office is checked rather than believed.
    show('d1', `a token WAS released in this name (entry ${answer.index})`, 'ok');
    show('d1-evidence', `opening ${answer.opening} — opens the published commitment at that position`);
  } else {
    // A negative answer has no object behind it, since an absence cannot be
    // exhibited, so it is signed under k_s^(O). Signing does not prevent an
    // office denying a token it minted; it makes the denial attributable.
    show('d1', `no token was released in this name (${answer.outcome})`,
         answer.outcome === 'NOT_RELEASED' ? 'ok' : 'warn');
    if (!answer.signed_denial) {
      show('d1-evidence', 'unsigned: the office said nothing you could rely on later', 'warn');
    } else {
      // Checked here rather than displayed. A signature shown and not
      // verified is indistinguishable from a signature that does not verify.
      const config = await pinned();
      const good = await verifyStatement(
        config.vro_statement_key,
        { statement: 'no-token-released', voter_id: credentials.voter_id },
        answer.signed_denial);
      show('d1-evidence', good
        ? 'denial verifies under the published k_p^(O) — keep it; it is attributable'
        : 'DENIAL DOES NOT VERIFY under the published k_p^(O)', good ? 'ok' : 'warn');
    }
  }
  $('d1-asof').textContent = stamp();
  await refresh();
}

/**
 * D2, the inclusion check.
 *
 * Two independent things, and the page keeps them apart because they fail
 * for different reasons. First: did the box really say this? That is the
 * signature, checked against the key pinned in the published configuration.
 * Second: does the registry still say it? That is the commitment published
 * at the stated position, read from the box but checkable against any
 * mirror of the head.
 *
 * Neither needs the box's cooperation beyond serving what it already
 * publishes, and neither trusts it: a box that denies a receipt it signed
 * is caught by the first, and one that drops an entry it acknowledged is
 * caught by the second.
 */
async function checkReceipt(receipt) {
  const config = await pinned();

  const authentic = await verifyStatement(
    config.ebb_statement_key,
    {
      accepted: receipt.accepted,
      election_id: config.election_id,
      entry_hash: receipt.entry_hash,
      index: receipt.index,
      reason: receipt.reason,
      statement: 'ballot-receipt',
    },
    receipt.signature);
  show('d2-signature', authentic
    ? `verifies under the published k_p^(B) for ${config.election_id}`
    : 'DOES NOT VERIFY under the published k_p^(B)', authentic ? 'ok' : 'warn');

  const view = await (await fetch(`${EBB}/published`)).json();
  const open = !('records' in view);
  const side = receipt.accepted ? 'accepted' : 'rejected';
  const entries = open ? view.commitments[side]
    : view.records[side].map((_, i) => ({ index: i }));
  const here = entries.find((e) => e.index === receipt.index);

  if (!here) {
    show('d2-inclusion', `no entry at position ${receipt.index} — the box has `
      + 'dropped an entry it signed for', 'warn');
  } else if (open) {
    const same = here.commitment === b64toHex(receipt.entry_hash);
    show('d2-inclusion', same
      ? `the commitment published at position ${receipt.index} is this entry`
      : `position ${receipt.index} now holds a DIFFERENT entry`, same ? 'ok' : 'warn');
  } else {
    show('d2-inclusion', `the record at position ${receipt.index} is released in `
      + 'clear; recompute its hash to compare', 'muted');
  }
  $('d2-asof').textContent = stamp();
}

const b64toHex = (t) => Array.from(unb64(t))
  .map((x) => x.toString(16).padStart(2, '0')).join('');

$('receipt').onchange = async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  let receipt;
  try { receipt = JSON.parse(await file.text()); }
  catch { show('d2-signature', 'That file is not a receipt.', 'warn'); return; }
  if (!receipt.signature) {
    show('d2-signature', 'That receipt carries no signature.', 'warn');
    return;
  }
  await checkReceipt(receipt);
};

refresh().catch((err) => show('status', `Could not read the published artefacts: ${err}`));
