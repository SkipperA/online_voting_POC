/** The checker. Reads published artefacts; holds nothing, signs nothing. */
const VRO = document.body.dataset.vroOrigin;
const EBB = document.body.dataset.ebbOrigin;
const $ = (id) => document.getElementById(id);
const show = (id, text, cls) => { const e = $(id); e.textContent = text; e.className = `value ${cls || ''}`; };

const stamp = () => new Date().toLocaleTimeString();

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
  show('recomputed', JSON.stringify(mine) + ' protest ' + JSON.stringify(protest));
  show('agree', same ? 'the box announced what the records say'
                     : 'DISAGREEMENT — the announced result does not follow', same ? 'ok' : 'warn');
  $('asof').textContent = `as of ${stamp()}`;
  show('status', 'Poll closed. Everything above was recomputed from published records.');
}

let CREDENTIALS = null;

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
    show('d1-evidence', answer.signed_denial
      ? `signed under k_s^(O): ${answer.signed_denial.slice(0, 44)}… — keep this`
      : 'unsigned: the office said nothing you could rely on later',
      answer.signed_denial ? '' : 'warn');
  }
  $('d1-asof').textContent = stamp();
  await refresh();
}

refresh().catch((err) => show('status', `Could not read the published artefacts: ${err}`));
