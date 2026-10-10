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
    for (const id of ['announced', 'recomputed', 'agree']) {
      show(id, 'not until the poll closes', 'muted');
    }
    show('ledger-state', 'withheld until the close; the chain is published now',
         'muted');
    $('asof').textContent = `as of ${stamp()}`;
    show('status', 'Voting is open. Contents are withheld; the chain is not.');
    return;
  }

  // Supersession among *accepted* ballots only. A rejected submission must
  // leave an earlier ballot untouched, or any reader of the box could annul
  // a stranger's vote by copying their public key and token.
  const latest = new Map();
  for (const r of accepted) latest.set(r.adhoc_public_key, r.selection);

  // Now that the records are open, the bound that holds can be checked:
  // distinct ad-hoc keys against tokens released. One token, one key, any
  // number of ballots under it.
  const within = latest.size <= log.count;
  show('count-audit',
       `${latest.size} distinct ad-hoc keys ≤ ${log.count} tokens released — ` +
       `${within ? 'holds' : 'VIOLATED'}`, within ? 'ok' : 'warn');
  const counts = {}, protest = {};
  for (const sel of latest.values()) {
    const inRange = Number.isInteger(sel) && sel >= 1;
    (inRange ? counts : protest)[sel] = ((inRange ? counts : protest)[sel] || 0) + 1;
  }
  const tally = await (await fetch(`${EBB}/tally`)).json();
  const announced = Object.fromEntries(
    Object.entries(tally.counts).filter(([, v]) => v > 0));
  const mine = Object.fromEntries(Object.entries(counts).filter(([, v]) => v > 0));
  const same = JSON.stringify(announced) === JSON.stringify(mine)
    && JSON.stringify(tally.protest_codes) === JSON.stringify(protest);
  show('announced', JSON.stringify(tally.counts) + ' protest ' + JSON.stringify(tally.protest_codes));
  show('ledger-state', 'released in clear — the download is the whole registry', 'ok');
  show('recomputed', JSON.stringify(mine) + ' protest ' + JSON.stringify(protest));
  show('agree', same ? 'the box announced what the records say'
                     : 'DISAGREEMENT — the announced result does not follow', same ? 'ok' : 'warn');
  $('asof').textContent = `as of ${stamp()}`;
  show('status', 'Poll closed. Everything above was recomputed from published records.');
}

let CREDENTIALS = null;

// Downloads rather than fetches: the file has to leave this origin to be
// worth anything. A verdict computed here is a verdict from a page the
// audited parties serve.
$('get-ledger').onclick = () => { window.location = `${EBB}/ledger`; };
$('get-releases').onclick = () => { window.location = `${VRO}/releases`; };
$('get-config').onclick = () => { window.location = `${CONFIG}/election.json`; };

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
