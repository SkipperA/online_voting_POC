/**
 * Three files in, every check out.
 *
 * The page parses nothing and verifies nothing itself: it posts the files
 * and renders what comes back. The checks are the ones in
 * tools/verify_election.py, run once rather than reimplemented here, so the
 * page and the command line cannot drift apart and quietly disagree.
 */
const $ = (id) => document.getElementById(id);
const escape = (s) => String(s).replace(/[&<>]/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

const files = { election: null, ledger: null, releases: null };

const LABEL = {
  election: 'election configuration',
  ledger: 'ballot box ledger',
  releases: 'release register',
};

/** Which of our files this is, by what is in it rather than what it is called. */
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

function ready() {
  $('run').disabled = !(files.election && files.ledger && files.releases);
}

/**
 * Each file is checked as it is chosen rather than at the end. A file in
 * the wrong place is then named at the moment it is put there, instead of
 * surfacing as a missing key somewhere inside the verification.
 */
function load(inputId, slot) {
  $(inputId).onchange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    // Kept verbatim. The configuration digest is over the bytes that were
    // served, so a file that has been through a parser and back is no
    // longer the file being checked.
    const text = await file.text();

    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      files[slot] = null;
      note(slot, `${file.name} is not JSON`, 'warn');
      ready();
      return;
    }

    const kind = kindOf(parsed);
    if (kind === 'supervision') {
      files[slot] = null;
      note(slot, 'that is the supervision register — it names citizens and is '
         + 'not part of this check', 'warn');
    } else if (kind && kind !== slot) {
      files[slot] = null;
      note(slot, `that is the ${LABEL[kind]}`, 'warn');
    } else if (!kind) {
      files[slot] = null;
      note(slot, `${file.name} is not one of these files`, 'warn');
    } else {
      files[slot] = text;
      note(slot, file.name, 'ok');
    }
    ready();
  };
}

load('f-election', 'election');
load('f-ledger', 'ledger');
load('f-releases', 'releases');

function render(report) {
  let group = null;
  const rows = report.checks.map((c) => {
    const heading = c.section !== group
      ? `<div class="group">${escape(c.section)}</div>` : '';
    group = c.section;
    return `${heading}<div class="check">
      <span class="verdict ${c.ok ? 'ok' : 'warn'}">${c.ok ? 'pass' : 'FAIL'}</span>
      <span>${escape(c.description)}${
        c.detail ? `<br><span class="detail">${escape(c.detail)}</span>` : ''}</span>
    </div>`;
  });
  $('checks').innerHTML = rows.join('');

  const t = report.tally;
  const options = Object.entries(t.options)
    .map(([k, n]) => `<div class="row"><span class="label">option ${escape(k)}</span><span class="value">${n}</span></div>`);
  const protest = Object.entries(t.outside_the_list)
    .map(([k, n]) => `<div class="row"><span class="label">outside the list: ${escape(k)}</span><span class="value">${n}</span></div>`);
  $('tally').innerHTML = `
    <div class="row"><span class="label">election</span><span class="value">${escape(t.election_id)}</span></div>
    <div class="row"><span class="label">configuration</span><span class="value">${escape(t.configuration_digest)}</span></div>
    ${options.join('')}${protest.join('')}
    <div class="row"><span class="label">ballots accepted</span><span class="value">${t.ballots} from ${t.voters} voters</span></div>
    <div class="row"><span class="label">rejected, published</span><span class="value">${t.rejected}</span></div>`;

  $('status').textContent = report.ok
    ? 'Every check passed. This result follows from the records in these files.'
    : `${report.checks.filter((c) => !c.ok).length} check(s) failed — the result above does not follow.`;
  $('status').className = report.ok ? 'ok' : 'warn';
}

$('run').onclick = async () => {
  $('status').textContent = 'Checking…';
  $('status').className = '';
  const response = await fetch('/check', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(files),
  });
  if (!response.ok) {
    $('status').textContent = (await response.json()).detail;
    $('status').className = 'warn';
    return;
  }
  render(await response.json());
  $('asof').textContent = `checked at ${new Date().toLocaleTimeString()}`;
};

$('get-script').onclick = () => { window.location = '/verify_election.py'; };
