/** The checker. Reads published artefacts; holds nothing, signs nothing. */
const VRO = document.body.dataset.vroOrigin;
const EBB = document.body.dataset.ebbOrigin;
const CONFIG = document.body.dataset.configOrigin;
const $ = (id) => document.getElementById(id);
const show = (id, text, cls) => { const e = $(id); e.textContent = text; e.className = `value ${cls || ''}`; };

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

$('refresh').onclick = () => refresh();
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
