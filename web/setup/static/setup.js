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

/**
 * One row per election on disk.
 *
 * Built as elements. The identifier is whatever an operator typed when the
 * election was minted, and `textContent` is the escape that cannot be
 * forgotten -- the same reason the ballot's option names are built this way.
 */
function electionRow(e, mayReplace) {
  const tr = document.createElement('tr');
  for (const text of [
    e.election_id || '—',
    e.directory,
    e.minted_at || '—',
    // Not "0 tokens". A poll that was never closed left no record, so the
    // figure is unknown rather than nought, and the two must not look alike.
    e.closed ? 'closed, with a record' : 'no record — interrupted',
    e.tokens_released === null ? '—' : String(e.tokens_released),
  ]) {
    const td = document.createElement('td');
    td.textContent = text;
    tr.append(td);
  }
  const action = document.createElement('td');
  if (e.served) {
    const now = document.createElement('b');
    now.textContent = 'served now';
    action.append(now);
  } else {
    const button = document.createElement('button');
    button.textContent = 'Serve';
    button.disabled = !mayReplace;
    button.onclick = () => serveElection(e.directory);
    action.append(button);
  }
  tr.append(action);
  return tr;
}

async function serveElection(directory) {
  const response = await fetch('/elections/serve', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ directory }),
  });
  if (!response.ok) { $('status').textContent = await problem(response); return; }
  const served = await response.json();
  await refresh();
  $('status').textContent = `Now serving ${served.election_id}. Every page `
    + 'open against the previous election must be reloaded — different keys, '
    + 'a different configuration, a different digest.';
}

/** What is on the disk, and whether the served election may be put aside. */
async function refreshElections() {
  const body = await (await fetch('/elections')).json();
  $('selector').hidden = !body.durable;
  $('replace-why').hidden = body.may_replace;
  $('replace-why').textContent = body.why_not || '';
  // The same rule governs both acts that replace the served election, so
  // the same answer disables both controls.
  $('mint').disabled = !body.may_replace;
  $('generate').disabled = !body.may_replace;

  // A run in progress survives the page being reloaded, so the page has to
  // find out about one it did not start.
  const run = await (await fetch('/elections/populate')).json();
  if (run.populating && !run.finished) {
    $('generate').disabled = true;
    $('mint').disabled = true;
    watchPopulate();
  }
  $('elections-rows').replaceChildren(
    ...body.elections.map((e) => electionRow(e, body.may_replace)));
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
  await refreshElections();

  const voters = (await (await fetch('/voters')).json()).voters;
  // Elements, not a template. An identifier is whatever an operator typed
  // -- `Kovács Ágnes` is the fixture, and `Nagy & Társa` is as legitimate
  // -- so it goes in as text. This was a template until the ballot's
  // option names made the same mistake visible one file away.
  if (voters.length) {
    $('register').replaceChildren(...voters.map((v) => {
      const li = document.createElement('li');
      li.textContent = v;
      return li;
    }));
  } else {
    const li = document.createElement('li');
    li.className = 'muted';
    li.textContent = 'nobody yet — the wallet will offer no personas';
    $('register').replaceChildren(li);
  }
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
  if (!response.ok) { $('status').textContent = await problem(response); return; }
  await refresh();
};

$('set-interval').onclick = async () => {
  const raw = $('interval').value.trim();
  const response = await fetch('/tally-interval', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ seconds: raw === '' ? null : Number(raw) }),
  });
  if (!response.ok) {
    $('status').textContent = await problem(response);
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
  if (!response.ok) { $('status').textContent = await problem(response); return; }
  await refresh();
  $('status').textContent = 'Schedule set. The configuration digest has changed.';
};

/**
 * What went wrong, as a sentence.
 *
 * An endpoint of ours answers `detail` with a sentence in it. FastAPI's own
 * validation layer answers `detail` with a *list* of objects, one per field
 * it could not read -- and a page that assumed the first shape printed
 * `[object Object]`, which is worse than no message at all: it says
 * something failed and nothing whatever about what. Both shapes are read
 * here, and anything else is shown raw rather than swallowed.
 */
async function problem(response) {
  let body;
  try {
    body = await response.json();
  } catch {
    return `${response.status} ${response.statusText}`;
  }
  const detail = body && body.detail;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    return detail.map((item) => {
      const field = Array.isArray(item.loc)
        ? item.loc.filter((part) => part !== 'body').join('.') : '';
      return field ? `${field}: ${item.msg}` : String(item.msg);
    }).join('; ');
  }
  return JSON.stringify(body);
}

/** Lines of a textarea, blanks dropped. A name may contain a comma. */
const linesOf = (id) => $(id).value
  .split('\n').map((s) => s.trim()).filter((s) => s !== '');

const optionLines = () => linesOf('mint-options');

/**
 * Counts, however they were typed: one per line, or commas, or spaces.
 *
 * Forgiving about the separator and strict about the value. A count that
 * is not a whole number used to reach the server as `null`, where it was
 * refused by a validation layer whose answer this page could not read --
 * so the one thing that would have said what was wrong was the thing that
 * broke. It is refused here instead, naming what it could not read.
 */
function countsOf(id) {
  const tokens = $(id).value.split(/[\s,]+/).filter(Boolean);
  const unreadable = tokens.filter((token) => !/^\d+$/.test(token));
  if (unreadable.length) {
    throw new Error(
      `not a count: ${unreadable.join(', ')} — one whole number per option, `
      + 'separated by commas, spaces or line breaks');
  }
  return tokens.map(Number);
}

/**
 * `-1:12, 99:3` as an object. Protest selections are recorded and never
 * interpreted, so this parses pairs and attaches no meaning to either half
 * -- but it does insist they are pairs, rather than quietly sending `NaN`
 * for anything it could not read.
 */
function parsePairs(text) {
  const out = {};
  for (const part of text.split(',').map((s) => s.trim()).filter(Boolean)) {
    const pair = /^(-?\d+)\s*:\s*(\d+)$/.exec(part);
    if (!pair) {
      throw new Error(
        `"${part}" is not a protest selection — write them as code:count, `
        + 'for example -1:12, 99:3');
    }
    out[pair[1]] = Number(pair[2]);
  }
  return out;
}

let watching = false;

/** Poll the run until it stops, then let the page catch up with it. */
async function watchPopulate() {
  if (watching) return;
  watching = true;
  try {
    for (;;) {
      const body = await (await fetch('/elections/populate')).json();
      if (!body.populating) return;
      if (body.finished) {
        $('generate-progress').textContent = body.error
          ? `Failed: ${body.error}`
          : `Done. The answer key is at ${body.answer_key} — it is served by `
            + 'nothing, and publishing its SHA-256 is what makes the challenge '
            + 'settleable.';
        await refresh();
        return;
      }
      $('generate-progress').textContent =
        `${body.phase} — ${body.done} of ${body.total}. Every other origin is `
        + 'refusing until this finishes.';
      await new Promise((resume) => { setTimeout(resume, 1000); });
    }
  } finally {
    watching = false;
  }
}

$('generate').onclick = async () => {
  let body;
  try {
    const names = linesOf('gen-options');
    const counts = countsOf('gen-counts');
    if (names.length && counts.length !== names.length) {
      throw new Error(
        `${counts.length} counts for ${names.length} options — the `
        + 'distribution has to be the same shape as the ballot');
    }
    body = {
      confirm: $('gen-confirm').value.trim(),
      election_id: $('gen-id').value.trim(),
      question: $('gen-question').value.trim() || null,
      options: names.length ? names : null,
      num_choices: names.length || counts.length,
      bits: Number($('gen-bits').value),
      per_option: counts,
      protest: parsePairs($('gen-protest').value),
      abstentions: Number($('gen-abstentions').value || 0),
      revotes: Number($('gen-revotes').value || 0),
    };
  } catch (badInput) {
    $('generate-progress').textContent = badInput.message;
    return;
  }
  $('generate').disabled = true;
  $('generate-progress').textContent = `Generating a ${body.bits}-bit modulus…`;
  const response = await fetch('/elections/generate', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    $('generate').disabled = false;
    $('generate-progress').textContent = await problem(response);
    return;
  }
  await watchPopulate();
};

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
  if (!response.ok) { $('status').textContent = await problem(response); return; }
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
