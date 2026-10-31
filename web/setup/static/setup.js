/** The setup console. Phase A, and nothing else. */
const $ = (id) => document.getElementById(id);

/**
 * The console has two states, and this is the whole of the difference.
 *
 * With nothing authored there is no fingerprint to compare, no register to
 * enrol into and no cadence to promise, so those sections are not shown
 * empty -- they are not shown. What is left is the one act that leaves the
 * state. `confirm` goes with them: it makes a destructive act take two
 * hands, and a first mint destroys nothing.
 */
function showFirstRun(first) {
  for (const section of document.querySelectorAll('.needs-election')) {
    section.hidden = first;
  }
  $('first-run').hidden = !first;
  $('mint-confirm-row').hidden = first;
  $('mint-destructive').hidden = first;
  $('mint-heading').textContent = first
    ? 'Create the first election' : 'Mint a new election';
  $('mint').textContent = first ? 'Create' : 'Mint';
}

async function refresh() {
  const c = await (await fetch('/configuration')).json();
  showFirstRun(!c.served);
  if (!c.served) {
    $('status').textContent = 'No election yet. Every other origin refuses '
      + 'until this console mints one.';
    return;
  }
  $('fingerprint').textContent = c.token_key_fingerprint;
  $('election').textContent = c.election_id;
  $('digest').textContent = c.digest;
  $('interval-now').textContent = c.tally_interval_seconds === null
    ? 'none — the close is the only publication point'
    : `${c.tally_interval_seconds} s`;
  $('register-size').textContent = `${c.register_size} voters`;
  $('choices-now').textContent = `${c.num_choices} options`;
  // `textContent`, not a template into `innerHTML`: these are the only
  // values on this page that an operator wrote in free text, and a name is
  // allowed to contain an ampersand or an angle bracket.
  $('question-now').textContent = c.question || '— none asked';
  $('options-now').textContent = c.options
    ? c.options.join(' · ') : '— the ballot is numbered';
  $('bits-now').textContent = `${c.token_key_bits} bits`;
  $('released-now').textContent = `${c.tokens_released} tokens released`;
  // The cadence is Phase A. Once the box is open the endpoint refuses it,
  // so the control says so rather than letting the operator find out from
  // a 409.
  $('interval').disabled = c.box_opened;
  $('set-interval').disabled = c.box_opened;
  $('interval-fixed').textContent = c.box_opened
    ? 'fixed — the ballot box is open' : '';
  $('phase-now').textContent = c.box_closed ? 'closed'
    : c.box_opened ? 'open — minting now discards this poll' : 'not yet opened';
  if (!$('opens').value) $('opens').value = c.opens;
  if (!$('closes').value) $('closes').value = c.closes;
  if (!$('mint-confirm').placeholder.includes(c.election_id)) {
    $('mint-confirm').placeholder = `type ${c.election_id} to confirm`;
  }
  const voters = (await (await fetch('/voters')).json()).voters;
  $('register').innerHTML = voters.length
    ? voters.map((v) => `<li>${v}</li>`).join('')
    : '<li class="muted">nobody yet — the wallet will offer no personas</li>';
  $('status').textContent = `${voters.length} on the register.`;
}

$('enrol').onclick = async () => {
  const voter_id = $('voter').value.trim();
  if (!voter_id) return;
  $('enrol').disabled = true;
  const response = await fetch('/voters', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ voter_id }),
  });
  $('voter').value = '';
  $('enrol').disabled = false;
  if (!response.ok) { $('status').textContent = 'Enrolment failed.'; return; }
  await refresh();
};

$('set-interval').onclick = async () => {
  const raw = $('interval').value.trim();
  const response = await fetch('/tally-interval', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ seconds: raw === '' ? null : Number(raw) }),
  });
  if (!response.ok) {
    $('status').textContent = (await response.json()).detail;
    return;
  }
  await refresh();
  $('status').textContent = 'Cadence set. The configuration digest has changed.';
};

$('set-schedule').onclick = async () => {
  const response = await fetch('/schedule', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ opens: $('opens').value, closes: $('closes').value }),
  });
  if (!response.ok) { $('status').textContent = (await response.json()).detail; return; }
  await refresh();
  $('status').textContent = 'Schedule set. The configuration digest has changed.';
};

/** The names, one per line, blanks dropped. A name may contain a comma. */
const optionLines = () => $('mint-options').value
  .split('\n').map((s) => s.trim()).filter((s) => s !== '');

// The list is the authority whenever there is one: an operator types names
// and the count follows them, rather than typing a number and being told by
// a 422 that it disagrees with what they typed above it. The server checks
// anyway -- a console that cannot produce a mismatch is a different thing
// from a server that would accept one.
$('mint-options').oninput = () => {
  const names = optionLines();
  if (names.length) $('mint-choices').value = String(names.length);
};

$('mint').onclick = async () => {
  const raw = $('mint-interval').value.trim();
  const names = optionLines();
  const body = {
    confirm: $('mint-confirm').value.trim(),
    election_id: $('mint-id').value.trim(),
    question: $('mint-question').value.trim() || null,
    options: names.length ? names : null,
    num_choices: names.length || Number($('mint-choices').value || 4),
    bits: Number($('mint-bits').value),
    opens: $('mint-opens').value.trim() || $('opens').value,
    closes: $('mint-closes').value.trim() || $('closes').value,
    tally_interval_seconds: raw === '' ? null : Number(raw),
    keep_register: $('mint-keep').checked,
  };
  $('mint').disabled = true;
  $('status').textContent = `Generating a ${body.bits}-bit modulus…`;
  const response = await fetch('/election', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  $('mint').disabled = false;
  if (!response.ok) { $('status').textContent = (await response.json()).detail; return; }
  const minted = await response.json();
  $('mint-confirm').value = '';
  $('mint-question').value = ''; $('mint-options').value = '';
  $('opens').value = ''; $('closes').value = '';
  await refresh();
  $('status').textContent = `Minted ${minted.election_id}. Every page open `
    + 'against the old election must be reloaded, and every token already '
    + 'issued is void.';
};

$('voter').onkeydown = (e) => { if (e.key === 'Enter') $('enrol').click(); };
refresh();
