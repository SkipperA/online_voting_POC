# System Architecture: Class and Sequence Diagrams

**Scope.** This document gives a code-level view of the package structure and
the protocol's runtime flow, as a companion to the specifications in
`docs/blind-signature.md` and `docs/protocol.md`. Where the technical article
(*Proposal for a Secure, Private, and Coercion-Resistant Online Voting
System*) numbers protocol steps (1/A, 5/1, 10/2, etc.), the sequence diagram
below cross-references the same numbers so the two documents can be read
side by side.

Both diagrams are derived directly from `src/ovpoc/*.py` as of the commit
that introduced this file. If the modules change, regenerate rather than
hand-edit -- the class diagram in particular is easy to let drift from the
actual field and method names.

**Two registers, two parties.** `PopulationRegister` is not part of the system:
it stands in for national identity infrastructure and lives in `driver/`,
outside the library, because the design consults it rather than builds it
(article §3.2). The library declares only the shape it needs, as the
`Certificate` and `CertificateLookup` protocols. The *electoral* register is
`VRO.register` -- a set of identifiers, and nothing else.

---

## 1. Class diagram

```mermaid
classDiagram
    direction LR

    class Voter {
        +voter_id: str
        +wallet: SigningKeyPair
        +vro_public_key: RSAPublicKey
        +pinned_vro_fingerprint: str
        -adhoc: SigningKeyPair
        -token: bytes
        -_blind_state: BlindState
        -recorded_heads: list~bytes~
        +build_auth_request() AuthRequest
        +accept_token(blind_sig: bytes)
        +cast(selection: int) Ballot
        +handle() VerificationHandle
        +verify_recorded_ballot(box, expected) bool
        +record_head(head: bytes)
    }

    class SigningKeyPair {
        -private: Ed25519PrivateKey
        +public_bytes: bytes
        +generate() SigningKeyPair
        +sign(data: bytes) bytes
    }

    class BlindState {
        +r_inv: int
        +encoded_msg: bytes
        +modulus: int
    }

    class AuthRequest {
        +voter_id: str
        +blinded_key: bytes
        +wallet_signature: bytes
        +signed_payload() bytes
        +to_dict() dict
    }

    class Ballot {
        +selection: int
        +adhoc_public_key: bytes
        +token: bytes
        +vote_signature: bytes
        +signed_payload() bytes
        +to_dict() dict
        +from_dict(d: dict) Ballot
    }

    class VerificationHandle {
        <<interface>>
        +locate(box: BallotBox) dict
        +confirms(box, expected_selection) bool
    }

    class AdHocKeyHandle {
        +adhoc: SigningKeyPair
        +transferable: bool
        +locate(box: BallotBox) dict
        +confirms(box, expected_selection) bool
        +prove_authorship(challenge: bytes) bytes
    }

    class VRO {
        +private_key: RSAPrivateKey
        +public_key: RSAPublicKey
        +population_register: CertificateLookup
        +office_key: SigningKeyPair
        +register: set~str~
        +release_log: Ledger
        -_released: set~str~
        -_nonces: Dict[str, bytes]
        -_audit: list~AuditEntry~
        +create(population_register, bits) VRO
        +enrol(voter_id)
        +office_public_key() bytes
        +audit_log() tuple~AuditEntry~
        +issue_token(request, now) TokenResponse
        +query_token_release(voter_id, signature) ReleaseAnswer
        +release_count() int
    }

    class Certificate {
        <<interface>>
        +subject: str
        +public_key: bytes
        +revoked: bool
        +is_expired(now) bool
    }

    class CertificateLookup {
        <<interface>>
        +lookup(person_id: str) Certificate
    }

    class PopulationRegister {
        +lookup(person_id) Certificate
        +enrol(person_id, public_key, ...) Certificate
        +revoke(person_id) Certificate
        +expire(person_id) Certificate
        +withdraw(person_id)
    }

    class TokenResponse {
        +outcome: Outcome
        +blind_signature: bytes
        +issued() bool
    }

    class Outcome {
        <<enumeration>>
        ISSUED
        NOT_IDENTIFIED
        CERTIFICATE_REVOKED
        CERTIFICATE_EXPIRED
        NOT_ELIGIBLE
        TOKEN_ALREADY_ISSUED
    }

    class AuditEntry {
        +voter_id: str
        +outcome: Outcome
        +reason: str
    }

    class ReleaseAnswer {
        +outcome: ReleaseOutcome
        +nonce: bytes
        +index: int
        +signed_denial: bytes
        +released() bool
    }

    class ReleaseOutcome {
        <<enumeration>>
        RELEASED
        NOT_RELEASED
        NOT_IDENTIFIED
    }

    class FaultDetected {
        <<exception>>
    }

    class BallotBox {
        +vro_public_key: RSAPublicKey
        +num_choices: int
        +tally_interval: int
        +accepted: Ledger
        +rejected: Ledger
        -_closed: bool
        -_snapshots: list~dict~
        +closed() bool
        +close()
        +submit(ballot: Ballot) SubmissionResult
        +published_view() dict
        +effective_ballots() dict
        +tally() dict
        +find_ballot(adhoc_public_key: bytes) dict
    }

    class BoxStillOpen {
        <<exception>>
    }

    class SubmissionResult {
        +accepted: bool
        +reason: str
        +ledger_head: bytes
    }

    class Ledger {
        +entries: list~Entry~
        +append(payload: dict) Entry
        +head() bytes
        +verify_chain() bool
    }

    class Entry {
        +index: int
        +payload: dict
        +prev_hash: bytes
        +entry_hash: bytes
    }

    class RSABSSA {
        <<module>>
        +generate_vro_keypair(bits) RSAPrivateKey
        +public_key_fingerprint(public_key) str
        +blind(public_key, msg) tuple
        +blind_sign(private_key, blinded_msg) bytes
        +finalize(public_key, msg, blind_sig, state) bytes
        +verify(public_key, msg, signature) bool
    }

    class Keys {
        <<module>>
        +verify_signature(public_bytes, signature, data) bool
        +generate_adhoc_keypair() SigningKeyPair
    }

    Voter "1" *-- "0..1" SigningKeyPair : wallet
    Voter "1" *-- "0..1" SigningKeyPair : adhoc
    Voter "1" *-- "0..1" BlindState : _blind_state (transient)
    Voter ..> AuthRequest : build_auth_request() creates
    Voter ..> Ballot : cast() creates
    Voter ..> AdHocKeyHandle : handle creates
    Voter ..> RSABSSA : blind() / finalize()

    AdHocKeyHandle ..|> VerificationHandle : implements
    AdHocKeyHandle o-- SigningKeyPair : refers to voter's adhoc key
    AdHocKeyHandle ..> BallotBox : locate() / confirms()

    VRO "1" *-- "1" Ledger : release_log
    VRO "1" o-- "1" CertificateLookup : population_register (external)
    VRO "1" *-- "1" SigningKeyPair : office_key (statements, not tokens)
    VRO "1" *-- "*" AuditEntry : private log
    VRO ..> AuthRequest : issue_token() consumes
    VRO ..> TokenResponse : issue_token() returns
    VRO ..> ReleaseAnswer : query_token_release() returns
    VRO ..> FaultDetected : raises on s_c^e != c
    VRO ..> RSABSSA : blind_sign() / check_blind_signature()
    VRO ..> Keys : verify_signature()

    PopulationRegister ..|> CertificateLookup : implements
    PopulationRegister ..> Certificate : lookup() returns
    TokenResponse o-- Outcome
    AuditEntry o-- Outcome
    ReleaseAnswer o-- ReleaseOutcome

    BallotBox ..> BoxStillOpen : tally() raises while open
    BallotBox "1" *-- "2" Ledger : accepted, rejected
    BallotBox ..> Ballot : submit() consumes
    BallotBox ..> SubmissionResult : submit() returns
    BallotBox ..> RSABSSA : verify()
    BallotBox ..> Keys : verify_signature()

    Ledger "1" *-- "*" Entry : entries
```

---

## 2. Sequence diagram

Step numbers in the notes (`step 3/4`, `10/1`, `12`, etc.) match the
numbering in the technical article and in `figures/Online_Voting_PIC.pdf`.

```mermaid
sequenceDiagram
    autonumber
    actor V as Voter
    participant W as Wallet (SigningKeyPair)
    participant P as PopulationRegister (external)
    participant O as VRO
    participant B as BallotBox
    participant L as Ledger

    rect rgb(230, 245, 255)
    Note over V,O: Registration -- steps 1-8
    V->>V: build_auth_request()<br/>generate_adhoc_keypair()
    V->>V: rsabssa.blind(vro_public_key, adhoc.public_bytes)<br/>[1/A, 1/B, 2]
    V->>W: sign(signed_payload())
    W-->>V: wallet_signature (s)
    Note right of V: AuthRequest[id, c, s] -- step 3/4

    V->>O: issue_token(request)
    activate O
    O->>P: lookup(voter_id) -- 5/1
    P-->>O: Certificate or None
    alt no certificate for this id
        O->>O: audit: "no entry for this id"
        O-->>V: TokenResponse(NOT_IDENTIFIED)
    else signature does not verify under cert.public_key -- 5/2
        O->>O: audit: "signature does not verify"
        O-->>V: TokenResponse(NOT_IDENTIFIED)
    else identity established
        Note over O: the identity boundary: only below it may<br/>the office give a specific reason
        alt cert.revoked / cert expired
            O-->>V: TokenResponse(CERTIFICATE_REVOKED / _EXPIRED)
        else voter_id not in register
            O-->>V: TokenResponse(NOT_ELIGIBLE)
        else already released a token
            O-->>V: TokenResponse(TOKEN_ALREADY_ISSUED)
        else
            O->>O: nonce = token_bytes(32)
            O->>L: release_log.append({commitment}) -- step 7
            O->>O: rsabssa.blind_sign(private_key, c) -- 6/A
            O->>O: check_blind_signature: s_c^e == c ?
            O-->>V: TokenResponse(ISSUED, s_c)
        end
    end
    deactivate O

    V->>V: accept_token(response.blind_signature)<br/>rsabssa.finalize(...) -- step 8
    Note right of V: token = s_{k_p^a}<br/>blind_state discarded
    end

    rect rgb(235, 250, 235)
    Note over V,L: Casting the ballot -- step 9-11
    V->>V: cast(selection)<br/>sign with adhoc key
    Note right of V: Ballot[i, k_p^a, token, s_vote]

    V->>B: submit(ballot)
    activate B
    B->>B: rsabssa.verify(vro_public_key,<br/>k_p^a, token) -- 10/1 valid voter?
    alt token not signed by VRO
        B->>L: rejected.append(ballot, reason)
        B-->>V: SubmissionResult(False, "token not signed by VRO")
    else
        B->>B: verify_signature(k_p^a, s_vote, ...) -- 10/2
        alt selection not authenticated
            B->>L: rejected.append(ballot, reason)
            B-->>V: SubmissionResult(False, "vote signature invalid")
        else accepted
            B->>L: accepted.append(ballot) -- 11/A
            B->>B: snapshot if tally_interval reached
            B-->>V: SubmissionResult(True, ledger_head)
        end
    end
    deactivate B
    V->>V: record_head(ledger_head)
    end

    rect rgb(255, 245, 230)
    Note over V,B: Independent verification, from any device -- steps 12-13
    V->>O: query_token_release(voter_id, sig(id))
    activate O
    O->>P: lookup(voter_id)
    P-->>O: Certificate or None
    O->>O: verify_signature(cert.public_key, sig, ...)
    alt unknown id or bad signature
        O-->>V: ReleaseAnswer(NOT_IDENTIFIED)
    else no token released
        O-->>V: ReleaseAnswer(NOT_RELEASED, signed under office_key)
    else
        O-->>V: ReleaseAnswer(RELEASED, nonce, index)
    end
    deactivate O
    V->>V: verify_release_answer(published_log, id, answer)<br/>checks nonce against O's own public log

    V->>B: handle.confirms(box, expected_selection)<br/>= find_ballot(adhoc_public_key)
    activate B
    B->>B: effective_ballots().get(k_p^a)
    B-->>V: recorded ballot or None
    deactivate B
    V->>V: compare recorded selection to intent
    end
```
