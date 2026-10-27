// The voter's surface over `POST /signed-token-requests`.
//
// It does two things and deliberately not a third. It shows what the document
// says, read out of the file in the browser before anything is sent, so the
// voter can compare it with what their application showed them. And it hands
// the bytes to the office and says what came back.
//
// What it does not do is decide anything. This page is served by the office,
// so a check it performed would be the audited party checking itself; the
// comparison that matters is the one the voter makes with their own
// application, and the one the office makes by rebuilding the document from
// the payload it recovered. Both of those happen somewhere else.

const MARKER = '%OVPOC-REQUEST ';

// Matches the server's cap. Checked here only so that a mistake is answered
// instantly rather than after uploading a film over a phone connection.
const LARGEST = 2 * 1024 * 1024;

const $ = (id) => document.getElementById(id);

/** The payload, out of the marker comment. A hint, exactly as it is for the
 *  office: nothing here is believed, and a document this fails to read may
 *  still be a perfectly good request. */
function payloadOf(bytes) {
  const text = new TextDecoder('latin1').decode(bytes);
  const at = text.indexOf(MARKER);
  if (at === -1) return null;
  const end = text.indexOf('\n', at);
  try {
    return JSON.parse(text.slice(at + MARKER.length, end === -1 ? undefined : end));
  } catch { return null; }
}

function unb64url(text) {
  const padded = text.replace(/-/g, '+').replace(/_/g, '/')
    + '='.repeat((4 - (text.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

/** The same four groups of four hex digits the document prints and the
 *  application shows. Sixty-four bits of SHA-256 over `c`. */
async function fingerprint(blindedKeyB64) {
  const digest = await crypto.subtle.digest('SHA-256', unb64url(blindedKeyB64));
  const hex = [...new Uint8Array(digest).slice(0, 8)]
    .map((b) => b.toString(16).padStart(2, '0')).join('');
  return hex.match(/.{4}/g).join('-');
}

function show(kind, headline, detail) {
  const box = $('outcome');
  box.className = `shown ${kind}`;
  $('headline').textContent = headline;
  $('detail').textContent = detail;
}

// One sentence per outcome, written here rather than sent by the office.
// The office returns the outcome and nothing else -- the reason it recorded
// is its own audit log's business and is never handed to a requester -- so
// the wording lives on the page, where a reader can see what each answer is
// taken to mean.
const OUTCOMES = {
  ISSUED: ['good', 'Your token has been released.',
    'Go back to the voting application and press Collect. Nothing else here '
    + 'concerns you.'],
  NOT_IDENTIFIED: ['bad', 'This office could not tell who signed that.',
    'Either the file carries no signature it can validate, or the certificate '
    + 'behind it does not chain to anything this office has been told to '
    + 'trust. It will not say which, and that is deliberate: an answer that '
    + 'distinguished them would let anybody test names against the electoral '
    + 'register.'],
  DOCUMENT_REFUSED: ['bad', 'That signature is good, and that document is not a token request.',
    'The office rebuilds the document from the values it carries and compares '
    + 'it with what you handed in. These did not match. Check that you '
    + 'uploaded the document your voting application wrote, as your wallet '
    + 'exported it, and that nothing edited it in between.'],
  CERTIFICATE_REVOKED: ['bad', 'The certificate that signed this has been revoked.',
    'Read from the revocation material your own wallet put into the document '
    + 'when it signed, so this is the status as of the moment you signed — '
    + 'this office does not ask your certification authority anything about '
    + 'you, deliberately. If that is a surprise, your certificate has been '
    + 'withdrawn and your wallet is where to find out why.'],
  CERTIFICATE_EXPIRED: ['bad', 'The certificate that signed this had expired.',
    'Its validity had run out before the moment of signing. Renewing it in '
    + 'your wallet and signing the same document again is all this needs; '
    + 'nothing about your request has to change.'],
  NOT_ELIGIBLE: ['bad', 'You are not on the electoral register for this election.',
    'The office administers that register; it does not populate it. Whoever '
    + 'maintains civil registration in this jurisdiction does.'],
  TOKEN_ALREADY_ISSUED: ['bad', 'A token has already been released for you.',
    'One citizen, one token, whichever way it was asked for. If you did not '
    + 'ask for it, that is worth reporting: the office keeps the request it '
    + 'acted on and cannot have manufactured it.'],
  REQUEST_PENDING: ['bad', 'A request for you is already waiting on an operator.', ''],
  ROUTE_NOT_OFFERED: ['bad', 'This office is not accepting signed documents.',
    'It has not been told which certificates to trust, so it offers no such '
    + 'route at all rather than refusing everyone who tries.'],
  TOO_LARGE: ['bad', 'That file is too large to be a token request.',
    'The office reads it into memory to check it, so it will not read an '
    + 'unbounded one from a stranger.'],
};

async function describe(bytes) {
  const payload = payloadOf(bytes);
  if (!payload) {
    $('w-election').textContent = 'not found in this file';
    $('w-digest').textContent = '—';
    $('w-fingerprint').textContent = '—';
    return;
  }
  $('w-election').textContent = payload.election_id ?? '—';
  $('w-digest').textContent = payload.config_digest ?? '—';
  $('w-fingerprint').textContent = payload.blinded_key
    ? await fingerprint(payload.blinded_key) : '—';
}

/** Which of the two S6 states this office is in, said on the page rather
 *  than left as a general statement about deployments. The clause names a
 *  substitution; whether it is in force here is a fact about this server,
 *  and a reader should not have to open the back office to learn it. */
(async () => {
  let trust;
  try {
    trust = await (await fetch('/back-office/trust')).json();
  } catch { return; }
  const where = $('s6-state');
  if (!where || !trust.offered) return;
  where.textContent = trust.trusted_list
    ? ` This office reads the ${trust.trusted_list.territory} trusted list,`
      + ` pinned ${trust.trusted_list.pinned_on}`
      + ` (${trust.trusted_list.days_old} days ago), so it can establish`
      + ' the word.'
    : ' This office is on a hand-pinned root, so it cannot establish the'
      + ' word and does not use it.';
})();

$('file').addEventListener('change', async (event) => {
  const file = event.target.files[0];
  $('outcome').className = '';
  if (!file) return;
  await describe(new Uint8Array(await file.arrayBuffer()));
});

$('send').addEventListener('click', async () => {
  const file = $('file').files[0];
  if (!file) {
    show('bad', 'Choose the signed document first.', '');
    return;
  }
  if (file.size > LARGEST) {
    const [kind, headline, detail] = OUTCOMES.TOO_LARGE;
    show(kind, headline, detail);
    return;
  }

  show('', 'Handing it in…', '');
  let body;
  try {
    const response = await fetch('/signed-token-requests', {
      method: 'POST',
      headers: { 'content-type': 'application/pdf' },
      body: await file.arrayBuffer(),
    });
    body = await response.json();
  } catch (error) {
    show('bad', 'The office could not be reached.', String(error));
    return;
  }

  const [kind, headline, detail] =
    OUTCOMES[body.outcome] ?? ['bad', `The office answered ${body.outcome}.`, ''];
  show(kind, headline, detail);
});
