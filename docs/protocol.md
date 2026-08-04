# Protocol mapping

Each numbered step below corresponds to a label in the system diagram
(*Anonymous Authenticated Ballot System*, 26 July 2026) and to the formal
description in Section 5 of the technical paper.

| Step | Paper notation | Code |
|---|---|---|
| 1/A | generate `k_s^a, k_p^a` | `keys.generate_adhoc_keypair` |
| 1/B, 2 | `c = f_{k_e}(k_p^a)` | `rsabssa.blind` |
| 3 | `s = sig_{k_s^(v)}(hash([id,c]))` | `SigningKeyPair.sign` on `AuthRequest.signed_payload` |
| 4 | send `[id, c, s]` | `Voter.build_auth_request` |
| 5, 5/1, 5/2 | validate request | `VRO.issue_token` |
| 6/A | `s_c = sig_{k_s^(R)}(c)` | `rsabssa.blind_sign` |
| 6/B | reject | `RegistrationError` |
| 7 | register the token release | `VRO.release_log` |
| 8 | `s_{k_p^a} = f_{k_d}(s_c)` | `rsabssa.finalize` |
| 9 | `[i, k_p^a, s_{k_p^a}, s_vote]` | `Voter.cast`, `messages.Ballot` |
| 10/1, 10/2 | validate ballot | `BallotBox.submit` |
| 11/A, 11/B | valid / rejected registries | `BallotBox.valid`, `.rejected` |
| 12 | independent token-release check | `VRO.token_released` |

## Concrete instantiation of the blinding

The paper requires that `f` be homomorphic with respect to `sig`, so that

    f_{k_d}( sig_{k_s^(R)}( f_{k_e}(k_p^a) ) ) = sig_{k_s^(R)}(k_p^a)

RSA supplies this directly through its multiplicativity. With modulus `n`,
public exponent `e`, and a blinding secret `r`:

    f_{k_e}(m) = PSS(m) · r^e mod n
    f_{k_d}(x) = x · r^{-1} mod n

so that

    (PSS(m) · r^e)^d · r^{-1} = PSS(m)^d mod n

which is an ordinary RSASSA-PSS signature over `m`. The construction follows
RFC 9474 (RSA Blind Signatures), variant RSABSSA-SHA384-PSS-Deterministic.

`PSS` is not decoration. Signing `m` directly would leave RSA's multiplicative
structure intact, letting a voter derive a signature on `m1·m2` from signatures
on `m1` and `m2`. See `test_multiplicative_forgery_is_defeated_by_pss_encoding`.
