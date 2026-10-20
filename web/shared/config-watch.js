/* Does the page still belong to the election it was opened for?
 *
 * ONE source, SEVEN copies at serve time, like `tokens.css` and for the
 * same reason: each origin's own application injects this into its own
 * pages (`service/apps.py:_page`). A `<script src>` pointing at 8000
 * would make six trust domains share a runtime dependency, and a page
 * that *executes* code from another origin is a worse version of that
 * than one that merely styles itself from it.
 *
 * The setup console is the seventh page and does not carry this. It is
 * the author of the change, and a console that told an operator to
 * reload because of the mint they had just performed would be reporting
 * its own act back to them as news.
 *
 * ---
 *
 * What goes wrong without it. Every page here pins the published
 * configuration when it loads -- the voter application pins the token
 * key's fingerprint, the wallet the digest it refuses a mismatch
 * against, the checker and the supervisor the statement keys every
 * signature on the page is verified under. The setup console can mint a
 * new election over the running one at any moment, and minting replaces
 * all three key pairs. Nothing tells the open pages.
 *
 * So they fail, and they fail in the place furthest from the cause: a
 * token that will not verify under the pinned fingerprint, a receipt
 * whose signature does not check, a release register whose head is
 * signed under a key the page has never seen. Each of those messages
 * names a real defence doing exactly its job, and in a room watching a
 * demonstration each of them reads as the system being broken. The
 * failure is honest and the diagnosis is unavailable.
 *
 * This is the diagnosis. It says nothing about whether any particular
 * check would pass; it says the page is looking at a superseded
 * election, which is the one fact that explains all of them at once.
 *
 * ---
 *
 * It watches the digest, not the configuration. `election.json.sha256`
 * is the published hash over the exact bytes of `election.json`, so any
 * change at all moves it -- a mint, a corrected schedule, a cadence
 * fixed before the box opens. All three mean the pinned copy is stale,
 * and distinguishing between them here would be this page deciding
 * which changes to the published configuration a reader is entitled to
 * ignore. It is also sixty-four characters rather than two kilobytes,
 * which is what makes polling it unobjectionable.
 *
 * The pin is the first digest this script reads, not the one any page
 * handed it. The script is injected into `<head>` and runs before the
 * page's own deferred script does, so its read is the earlier one: a
 * mint landing between the two leaves the page holding a configuration
 * *newer* than the pin, and the next poll raises the banner for a page
 * that is in fact current. That is the direction to be wrong in. The
 * other arrangement -- pinning late and missing a change that landed
 * early -- is a page quietly showing a superseded election, which is
 * the whole of what this exists to prevent.
 */
(() => {
  const ORIGIN = window.OVPOC_CONFIG_ORIGIN;
  if (!ORIGIN) return;

  // Often enough that the banner beats the failure it explains, rarely
  // enough that it is not a feature of the network traffic a reader is
  // being shown. The file is static and inert; the config origin
  // computes nothing to answer this.
  const EVERY = 5000;

  let pinned = null;
  let raised = false;

  async function digest() {
    // `no-store`, because the one thing this must not read is a cached
    // copy of the artefact whose change it is watching for.
    const response = await fetch(`${ORIGIN}/election.json.sha256`,
                                 { cache: 'no-store' });
    if (!response.ok) throw new Error(String(response.status));
    return (await response.text()).trim().split(/\s+/)[0];
  }

  /** The bar. Built here so that no page can be served without it. */
  function raise(was, now) {
    if (raised) return;
    raised = true;

    const bar = document.createElement('div');
    bar.className = 'stale';
    bar.setAttribute('role', 'alert');

    const said = document.createElement('div');
    said.className = 'stale-said';
    said.innerHTML = '<b>The published configuration has changed '
      + 'since this page was opened.</b>'
      + '<span class="stale-why">This page pinned the election it loaded '
      + 'with, and that election has been superseded — most likely by '
      + 'a mint from the setup console, which replaces all three key '
      + 'pairs. Anything computed here belongs to the earlier one: tokens '
      + 'no longer verify, receipts are no longer evidence, and the '
      + 'failures this page reports from now on are about the wrong '
      + 'election rather than about anything wrong.</span>'
      + '<span class="stale-digests"></span>';
    // Set as text, not markup: these are values read off another origin,
    // and the page has no business trusting their shape.
    said.querySelector('.stale-digests').textContent =
      `pinned ${was.slice(0, 16)}… · published now ${now.slice(0, 16)}…`;

    const reload = document.createElement('button');
    reload.textContent = 'Reload this page';
    // The bar never navigates on its own. On the voter application a
    // reload costs the voter the ad-hoc key and with it the entitlement
    // to re-vote, which is the design's own answer to coercion; the
    // page's `beforeunload` guard is what stands in the way, and it
    // fires on this click like any other.
    reload.onclick = () => window.location.reload();

    const keep = document.createElement('button');
    keep.textContent = 'Keep this page as it is';
    // Collapses, and does not close. The condition is permanent until
    // the page is reloaded, so a notice that could be dismissed outright
    // would leave a stale page looking exactly like a current one --
    // which is the state this script exists to make impossible.
    keep.onclick = () => bar.classList.add('stale--slim');

    const controls = document.createElement('div');
    controls.className = 'stale-controls';
    controls.append(reload, keep);

    bar.append(said, controls);

    /* The band sticks beneath this bar rather than behind it. Both are
     * permanent notices and the band is the only thing on the page that
     * says which trust domain the reader is standing in, so neither may
     * hide the other.
     *
     * Measured rather than declared: the bar's height is whatever its
     * text wraps to, which depends on the viewport, on the reader's font
     * size, and on whether the bar has been collapsed. A constant here
     * would be right at one window width. */
    const measure = () => document.documentElement.style.setProperty(
      '--stale-height', `${bar.offsetHeight}px`);
    if (window.ResizeObserver) new ResizeObserver(measure).observe(bar);
    else window.addEventListener('resize', measure);

    // This script is injected into `<head>`, so on a page still parsing
    // there is no body to put the bar in. It cannot happen in practice
    // -- the bar is raised on the second poll at the earliest, five
    // seconds in -- but a notice that throws instead of appearing would
    // fail in precisely the silent way the rest of this file is about.
    const put = () => { document.body.prepend(bar); measure(); };
    if (document.body) put();
    else document.addEventListener('DOMContentLoaded', put, { once: true });
  }

  async function look() {
    let now;
    try {
      now = await digest();
    } catch {
      // The config origin being unreachable is its own problem and not
      // this one. Saying nothing is right: a page that cried staleness
      // every time a fetch failed would be ignored by the time it had
      // something to say.
      return;
    }
    if (pinned === null) { pinned = now; return; }
    if (now !== pinned) raise(pinned, now);
  }

  look();
  setInterval(look, EVERY);
  // Returning to a tab is when a mint is most likely to have happened
  // while nobody was watching, and is also the moment a reader is about
  // to believe what is on the screen.
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) look();
  });
})();
