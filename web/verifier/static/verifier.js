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
const names = { election: null, ledger: null, releases: null };

const LABEL = {
  election: 'election configuration',
  ledger: 'ballot box ledger',
  releases: 'release register',
};

/** Which of the three a file is, by what is in it rather than where it was put. */
function kindOf(text) {
  let parsed;
  try { parsed = JSON.parse(text); } catch { return null; }
  if (String(parsed.format || '').startsWith('ovpoc-ledger')) return 'ledger';
  if (String(parsed.format || '').startsWith('ovpoc-releases')) return 'releases';
  if ('vro_token_key_spki' in parsed) return 'election';
  return null;
}

function state() {
  for (const key of Object.keys(files)) {
    const slot = $(`have-${key}`);
    slot.textContent = files[key] ? names[key] : 'not loaded';
    slot.className = `value ${files[key] ? 'ok' : 'muted'}`;
  }
  $('run').disabled = !(files.election && files.ledger && files.releases);
}

/**
 * Files are assigned by content, not by which input they were dropped on.
 * Three inputs and three files is three chances to get the pairing wrong,
 * and the first person to use this page got a bare KeyError for their
 * trouble.
 */
async function accept(fileList) {
  for (const file of fileList) {
    // Kept verbatim. The configuration digest is over the bytes that were
    // served, so a file that has been through a parser and back is no
    // longer the file being checked.
    const text = await file.text();
    const kind = kindOf(text);
    if (!kind) {
      $('status').textContent = `${file.name} is not one of the three files.`;
      $('status').className = 'warn';
      continue;
    }
    files[kind] = text;
    names[kind] = file.name;
    $('status').textContent = `${file.name} read as the ${LABEL[kind]}.`;
    $('status').className = '';
  }
  state();
}

$('pick').onchange = (e) => accept(e.target.files);

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
