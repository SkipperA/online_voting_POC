# The Blind Signature Chain: Exact Specification

**Scope.** This document specifies the sequence of mappings applied to the voter's
ad-hoc public key $k_p^a$ between its generation in the Voter App and its
appearance in the public ballot box as a VRO-certified token. It fixes every
parameter, states where each parameter comes from, proves correctness, and lists
the checks that must not be omitted.

It is the normative reference for `rsabssa.py` and for the token-issuance path in
`vro.py` and `voter.py`.

Notation follows the technical article (*Proposal for a Secure, Private, and
Coercion-Resistant Online Voting System*, §4.1 and §5).

---

## 1. Entities

| Symbol | Entity | Role in this document |
|---|---|---|
| VA | Voter App | Generates $k_p^a$, blinds, unblinds, verifies, casts |
| Wallet | Digital Identity Wallet | Signs the authentication request; holds $k_s^{(v)}$ |
| VRO | Voter Registration Office | Applies the raw private-key operation to the blinded value |
| BB | Ballot Box service | Verifies the token and the ballot signature; publishes both |

The VRO and the BB are separate subsystems and are assumed not to collude for the
anonymity argument of §6.1. The Wallet is separate from the VA (article §3.5).

---

## 2. Parameters

### 2.1 VRO signing key — one pair for the whole election

$$
p_R,\, q_R \ \text{prime},\qquad
n_R = p_R\, q_R,\qquad
\lambda(n_R) = \mathrm{lcm}(p_R - 1,\; q_R - 1)
$$

$$
\gcd\left(e_R,\, \lambda(n_R)\right) = 1,
\qquad
d_R \equiv e_R^{-1} \pmod{\lambda(n_R)}
$$

| Parameter | Value / constraint | Provenance |
|---|---|---|
| $e_R$ | 65537 | Fixed by RFC 9474; pinned in the election crypto profile |
| $\lvert n_R \rvert$ | 4096 bits (the size RFC 9474 pairs with the SHA-384 variants); 3072 is the floor | Key ceremony |
| $p_R, q_R$ | Hardware RNG inside an HSM; never exported | Key ceremony under $M$-of-$N$ custody |
| $d_R$ | Non-exportable, single-purpose (§6.3) | Key ceremony |
| $k_p^{(R)} = (n_R, e_R)$ | Published **before** registration opens; pinned in the VA | Public registry / election root CA |

The requirement that there be exactly **one** pair, published and pinned, is not a
convenience. It carries the anonymity guarantee: a VRO issuing per-voter keys
could afterwards determine which of its keys verifies a given ballot and re-link
it. See article §3.2, *A single signing key for all voters*, and `CLAUDE.md`.

### 2.2 Ad-hoc key pair — fresh per voter per election

$$
k_s^a \xleftarrow{\ \$\ } \{0,1\}^{256},
\qquad
k_p^a = \text{Ed25519-PublicKey}(k_s^a)
$$

| Parameter | Value / constraint | Provenance |
|---|---|---|
| $k_s^a$ | 32 bytes, OS CSPRNG | VA, at registration; zeroised after the close of voting |
| $k_p^a$ | 32 bytes, RFC 8032 point encoding | Derived; becomes the message signed by the VRO |
| Lifetime | One election | Never reused; reuse links two elections |

$k_p^a$ is the **message** in the blind signature protocol. Everything below
operates on it.

### 2.3 PSS salt

| Parameter | Value | Provenance |
|---|---|---|
| Hash | SHA-384, $h_{\text{Len}} = 48$ | RFC 9474 variant `RSABSSA-SHA384-PSS-Deterministic` |
| MGF | MGF1 with SHA-384 | Same |
| $s_{\text{Len}}$ | 48 bytes | Same |
| salt | Fresh random 48 bytes | **Chosen by the VA**, inside `Blind()` |

> **Erratum for the article.** §4.1 states that the encoding is "randomised by a
> salt the signing party chooses." In RFC 9474 the *client* performs
> `EMSA-PSS-ENCODE` inside `Blind()`; the signer never sees an unencoded message
> and therefore cannot choose the salt. The salt is chosen by the voter. The
> substantive point the sentence makes — that $\mathrm{enc}(m)$ denotes one
> encoding among many rather than a function of $m$ alone — is unaffected.

*Deterministic* in the variant name refers to the message-preparation step
(`PrepareIdentity`: the message is passed through unchanged, with no random
prefix), not to the salt.

### 2.4 Blinding factor

$$
r \xleftarrow{\ \$\ } \mathbb{Z}_{n_R}^{*}
\qquad\text{i.e.}\qquad
r \in [1,\, n_R - 1] \ \text{ with } \ \gcd(r,\, n_R) = 1
$$

| Parameter | Constraint | Provenance |
|---|---|---|
| $r$ | Uniform on $\mathbb{Z}_{n_R}^{*}$ | VA, OS CSPRNG, fresh per registration |
| $r^{-1}$ | Extended Euclid mod $n_R$ | VA, computed at blinding time and retained until unblinding |
| Lifetime | Discarded immediately after §4 step (4) succeeds | — |

If the draw ever yields $\gcd(r, n_R) \neq 1$, the VA has factored $n_R$. This is
not an error to retry silently: abort and raise an alarm.

---

## 3. The two encodings, kept apart

The article uses two distinct maps and the protocol breaks if they are conflated.

$$
\text{sig}_{k_s}(m) \;=\; S\!\left(\mathrm{enc}(m)\right)
$$

- $\mathrm{enc}(\cdot)$ — **padded encoding.** `EMSA-PSS-ENCODE`, performed by the
  **VA**. Maps 32 bytes of Ed25519 public key to an integer mod $n_R$.
- $S(\cdot)$ — **raw private-key operation.** $S(x) = x^{d_R} \bmod n_R$,
  performed by the **VRO**.

The VRO applies $S$ and only $S$. It must not apply $\text{sig}$, because the
value it receives has already been encoded by the voter; encoding it a second
time would destroy the blinding and produce a signature on nothing.

### 3.1 `EMSA-PSS-ENCODE`, expanded

With $\text{modBits} = \lvert n_R \rvert$, $\text{emBits} = \text{modBits} - 1$,
$\text{emLen} = \lceil \text{emBits}/8 \rceil$:

1. $\text{mHash} = \text{SHA-384}(k_p^a)$, 48 bytes
2. $\text{salt} \xleftarrow{\$} \{0,1\}^{384}$, 48 bytes
3. $M' = \underbrace{\texttt{00}\cdots\texttt{00}}_{8 \text{ bytes}} \,\Vert\, \text{mHash} \,\Vert\, \text{salt}$
4. $H = \text{SHA-384}(M')$
5. $\text{PS} = \texttt{00}^{\,\text{emLen} - s_{\text{Len}} - h_{\text{Len}} - 2}$
6. $\text{DB} = \text{PS} \,\Vert\, \texttt{01} \,\Vert\, \text{salt}$
7. $\text{dbMask} = \text{MGF1}(H,\ \text{emLen} - h_{\text{Len}} - 1)$
8. $\text{maskedDB} = \text{DB} \oplus \text{dbMask}$, then zero the leftmost
   $8 \cdot \text{emLen} - \text{emBits}$ bits
9. $\text{EM} = \text{maskedDB} \,\Vert\, H \,\Vert\, \texttt{bc}$

$$
\bar{m} \;=\; \mathrm{enc}(k_p^a) \;=\; \text{OS2IP}(\text{EM})
$$

Well-formedness requires $\text{emLen} \geq h_{\text{Len}} + s_{\text{Len}} + 2 = 98$
bytes. A 4096-bit modulus gives $\text{emLen} = 512$; ample.

---

## 4. The mapping chain

### (1) Blinding — VA

$$
\boxed{\;c \;=\; \mathrm{enc}(k_p^a) \cdot r^{\,e_R} \;=\; \bar{m} \cdot r^{\,e_R} \pmod{n_R}\;}
$$

**Guard before sending:** $\gcd(\bar{m},\, n_R) = 1$. If it fails, restart with a
new $k_s^a$ — do not send.

### (2) Authentication request — VA, Wallet, VRO

$$
s \;=\; \text{sig}_{k_s^{(v)}}\!\left(\text{hash}([\,id,\, c\,])\right)
$$

The package $[\,id,\, c,\, s\,]$ goes to the VRO. The VRO checks that $id$ is on
the electoral register, that $s$ verifies under the registered wallet key
$k_p^{(v)}$, and that no token has yet been released for $id$.

Note that $c$ carries no information about $k_p^a$ (§6.1), so the VRO may log it
without weakening anonymity. The release entry itself is a *commitment* to $id$,
not $id$ in clear — see `docs/threats.md`.

### (3) Blind signing — VRO

$$
\boxed{\;s_c \;=\; S(c) \;=\; c^{\,d_R} \pmod{n_R}\;}
$$

**Guards inside the VRO:**

- $0 \leq c < n_R$, and $c$ is exactly $\lceil \lvert n_R \rvert / 8 \rceil$ bytes.
- After computing $s_c$, verify $s_c^{\,e_R} \equiv c \pmod{n_R}$ before
  releasing it. This is cheap ($e_R = 65537$) and catches a fault during the
  CRT exponentiation; a single faulty CRT signature leaks $p_R$
  (Boneh–DeMillo–Lipton).

### (4) Unblinding and verification — VA

$$
\boxed{\;s_{k_p^a} \;=\; s_c \cdot r^{-1} \pmod{n_R}\;}
$$

$$
\boxed{\;\left(s_{k_p^a}\right)^{e_R} \bmod n_R \;\overset{?}{=}\; \mathrm{enc}(k_p^a)\;}
$$

Equivalently, and preferably in code: run a stock `RSASSA-PSS-VERIFY` over
$(k_p^{(R)},\, k_p^a,\, s_{k_p^a})$ using an unmodified library. The point of
RFC 9474 is that this works.

**The verification is mandatory, not advisory.** It is the only moment at which
the voter learns whether the VRO behaved. It must run before $r$ is zeroised. If
it fails, the voter's one-token-per-voter flag has already been consumed at the
VRO, so the system needs a documented re-issuance path with an audit trail —
this is a deployment requirement, not a cryptographic one.

### (5) Casting — VA to BB, over the anonymising channel

$$
s_{vote} \;=\; \text{sig}_{k_s^a}\!\left(\text{hash}([\,i,\, k_p^a\,])\right)
$$

$$
\text{ballot} \;=\; \left[\,i,\ k_p^a,\ s_{k_p^a},\ s_{vote}\,\right]
$$

The BB accepts the ballot iff $s_{k_p^a}$ verifies against the published
$k_p^{(R)}$ **and** $s_{vote}$ verifies under $k_p^a$. Supersession applies only
among accepted ballots; see article §5.6 on the two senses of "invalid".

---

## 5. Correctness

Since $e_R d_R \equiv 1 \pmod{\lambda(n_R)}$, we have $x^{e_R d_R} = x$ for every
$x \in \mathbb{Z}_{n_R}^{*}$. Hence

$$
s_c \cdot r^{-1}
\;=\; \left(\bar{m} \cdot r^{\,e_R}\right)^{d_R} r^{-1}
\;=\; \bar{m}^{\,d_R} \cdot r^{\,e_R d_R} \cdot r^{-1}
\;=\; \bar{m}^{\,d_R} \cdot r \cdot r^{-1}
\;=\; \bar{m}^{\,d_R}
$$

$$
\;=\; S\!\left(\mathrm{enc}(k_p^a)\right)
\;=\; \text{sig}_{k_s^{(R)}}(k_p^a) \pmod{n_R}
$$

$\blacksquare$

The step $r^{\,e_R d_R} = r$ is the one that is routinely misread. The voter
multiplies by $r^{e_R}$ and divides by $r$, *not* by $r^{e_R}$: the exponent is
consumed by the signing operation. Blinding and unblinding are therefore not
inverse operations, and the identity must not be read as though the blinding
could be stripped before the signature is applied.

---

## 6. What the construction guarantees

### 6.1 Blindness is perfect, not computational

The map $x \mapsto x^{e_R}$ is a bijection on $\mathbb{Z}_{n_R}^{*}$. Since $r$ is
uniform on $\mathbb{Z}_{n_R}^{*}$, so is $r^{e_R}$, and therefore so is
$c = \bar{m} \cdot r^{e_R}$ — independently of $\bar{m}$. For any candidate
$\bar{m}'$ there exists exactly one $r' = (c \cdot \bar{m}'^{-1})^{d_R}$ that
explains the transcript.

The consequence: an **unbounded** VRO, even colluding with the BB, gains nothing
from the issuance log about which ballot belongs to which voter. This is an
information-theoretic statement, not one resting on a hardness assumption, and it
does not decay over time.

It is also fragile in one specific way. Blindness is a statement about the
*algebraic* transcript only. Network metadata, timing correlation between
registration and casting, or a shared device fingerprint re-link the voter
outside the algebra entirely. Article §3.7 states this; `docs/threats.md`
records what the POC does and does not defend.

### 6.2 One-more unforgeability

RSA blind signatures with a full-domain-style encoding are one-more unforgeable
in the random oracle model under the RSA known-target inversion assumption
(Bellare, Namprempre, Pointcheval, Semanko, *J. Cryptology* 16(3), 2003). This is
what prevents a voter from turning $N$ interactions with the VRO into $N+1$ valid
tokens.

Two conditions the reduction needs, both easy to lose in implementation:

- $e_R$ must be prime. 65537 is.
- The encoding must be applied. Signing $k_p^a$ raw leaves RSA's multiplicative
  structure intact: a voter holding tokens on $k_1$ and $k_2$ could compute a
  valid token on $k_1 k_2 \bmod n_R$ that the VRO never issued. PSS destroys
  this — the product of two encodings is not, except with negligible
  probability, the encoding of anything.

The ROS/Wagner attacks that break concurrent blind Schnorr do not apply to the
RSA construction.

### 6.3 The signing key must be single-purpose

A blind signer is, by construction, an oracle that computes $x \mapsto x^{d_R}$
on values it cannot inspect. No amount of structural checking helps, because
there is nothing to check: $c$ is uniformly random by §6.1.

Therefore $d_R$ must be used for **nothing else** — no TLS, no document signing,
no other election, no test runs against the production key. Any protocol that
treats an RSA signature under $k_p^{(R)}$ as meaningful for another purpose is
forgeable by any voter who registered.

### 6.4 `PrepareIdentity` is safe here — for a specific reason

RFC 9474 offers `PrepareRandomize` (prefixing 32 random bytes to the message) and
`PrepareIdentity` (passing it through). The randomised preparation exists to
protect applications where the message is low-entropy or is chosen by the signer
or an adversary.

Neither holds here. The message is $k_p^a$: 32 bytes derived from a freshly drawn
256-bit secret, generated by the voter's own device, never seen by the VRO. The
deterministic variant is therefore appropriate — and it is also what makes the
token a signature on the key itself rather than on a prefixed blob, which is what
lets the BB's check be a plain library verification.

If the message ever becomes something the VRO or a third party influences, this
choice must be revisited.

---

## 7. What the construction does not guarantee

Recorded here so that the file is not read as claiming more than it proves.

1. **It does not make the voter's ballot unprovable to third parties.** The
   current implementation is Variant B: the voter locates the ballot by the
   ad-hoc key they control, which means authorship is provable to an adjudicator
   and, unavoidably, equally to a coercer. Variant A (anonymous random-number
   tracker, Selene-style) is documented as future work. This is the
   verifiability/coercion tension of article §1 and is a legislative choice, not
   a defect to be patched.
2. **It does not prevent a dishonest VRO from minting tokens for citizens who
   did not vote.** Blindness cuts both ways: the VRO cannot link a token to a
   voter, and neither can an auditor. The count-based audit bounds the number of
   tokens; it cannot attribute them. The remedy is institutional — distributed
   issuance among mutually independent authorities.
3. **It does not protect the voter's device.** A compromised VA holds $k_s^a$ and
   can cast a silent overriding ballot after the voter's final check. See article
   §3.6.
4. **It does not provide availability.** Signing makes the channel an
   integrity-preserving carrier of bits; it does nothing about dropped, delayed,
   or selectively blocked ballots.

---

## 8. Implementation checklist

Each item below has caused a real failure in some deployed blind-signature system
or is enforced by a test in `tests/`.

- [ ] $k_p^{(R)}$ pinned in the VA and identical for every voter; the VA rejects a
      signature verifying under any other key.
- [ ] VRO applies $S$, never $\text{sig}$ — no second encoding.
- [ ] VA checks $\gcd(\bar{m}, n_R) = 1$ before blinding.
- [ ] VA draws $r$ from the OS CSPRNG, fresh per registration, never from an
      application-seeded PRNG.
- [ ] VRO range-checks $c$ and verifies $s_c^{\,e_R} \equiv c$ before release.
- [ ] VA verifies the unblinded signature before discarding $r$.
- [ ] $d_R$ is single-purpose and non-exportable; CRT exponentiation is blinded
      and constant-time.
- [ ] $r$ and $k_s^a$ are zeroised at their defined end of life.
- [ ] Registration and casting are separated in time and routed over an
      anonymising channel.
- [ ] $N_{\text{released}}$ (VRO) and $N_{\text{accepted}}$ (BB) are published;
      $N_{\text{accepted}} \leq N_{\text{released}}$ is checkable by anyone.

---

## 9. Mapping to the code

| Specification step | Module | Function |
|---|---|---|
| §3.1 encoding | `rsabssa.py` | `emsa_pss_encode` |
| §4 (1) blinding | `rsabssa.py` | `blind` |
| §4 (3) blind signing | `rsabssa.py`, `vro.py` | `blind_sign`, `issue_token` |
| §4 (4) unblinding + verify | `rsabssa.py` | `finalize` |
| §4 (5) casting | `voter.py` | `cast` |
| §4 (5) acceptance | `ballotbox.py` | `submit` |
| §2.1 key pinning | `keys.py` | — |

---

## 10. References

- D. Chaum (1983). *Blind Signatures for Untraceable Payments.* CRYPTO '82, 199–203.
- A. Fujioka, T. Okamoto, K. Ohta (1993). *A Practical Secret Voting Scheme for Large Scale Elections.* AUSCRYPT '92, LNCS 718, 244–251.
- M. Bellare, C. Namprempre, D. Pointcheval, M. Semanko (2003). *The One-More-RSA-Inversion Problems and the Security of Chaum's Blind Signature Scheme.* J. Cryptology 16(3), 185–215.
- D. Boneh, R. DeMillo, R. Lipton (1997). *On the Importance of Checking Cryptographic Protocols for Faults.* EUROCRYPT '97, LNCS 1233, 37–51.
- K. Moriarty, B. Kaliski, J. Jonsson, A. Rusch (2016). *PKCS #1: RSA Cryptography Specifications Version 2.2.* RFC 8017.
- F. Denis, F. Jacobs, C. A. Wood (2023). *RSA Blind Signatures.* RFC 9474.
- S. Josefsson, I. Liusvaara (2017). *Edwards-Curve Digital Signature Algorithm (EdDSA).* RFC 8032.
- P. Y. A. Ryan, P. B. Rønne, V. Iovino (2016). *Selene: Voting with Transparent Verifiability and Coercion-Mitigation.* VOTING '16, LNCS 9604, 176–192.
