# 0009. Token and invite format

Status: Accepted, amended
Date: 2026-11-22

## Context

Network mode authenticates every request with a bearer token, and people join boards with
single-use invites. Both are secrets that travel through terminals, chat and environment
variables. They must be recognisable (so a leak can be found by scanning, and a token is not
mistaken for an invite), checkable without storing them, and cheap to look up.

## Decision

- **Shape.** A token is `stg1_<id>_<secret>`, an invite `stgi1_<id>_<secret>`
  (`stigmer_core::credentials`). `id` is 8 random bytes as 16 lowercase hex characters: a lookup
  key, not a secret, shown by `token list` and in the security log. `secret` is 32 random bytes
  as 43 base64url characters (no padding). The `1` is a format version. `parse_secret` accepts
  exactly this shape for the expected kind, so a token never parses as an invite or the reverse,
  and its errors never echo the input.
- **Storage.** Only `sha256(secret)` is stored, next to the id, scope, principal, expiry,
  revocation time and last-seen time. The secret is returned once (by `enable-auth`,
  `new-instance-token`, `issue-member-token`, `invite create` or `join`) and never stored,
  logged or echoed. A slow password hash is not needed: the secret has 256 bits of entropy.
- **Verification.** Look up by id, then compare the hashes with `hashes_match`, which XOR-folds
  all 32 bytes with no early exit. An unknown id is compared against a fixed dummy hash
  (`DUMMY_HASH` for tokens, `UNKNOWN_INVITE_HASH` for invites), so a miss does the same hash work
  as a wrong secret. Then expiry, revocation and (for a board token) membership are checked.
  Every failure is the same 401 ([0011](0011-authentication-policy-401-403-404.md)).
- **Lifetimes.** A token from `join` lives 90 days. The instance token lives 90 days by default
  (`new-instance-token --expires-days`, 1 to 365). An invite lives 60 minutes by default and at
  most 7 days (`invite create --expires`); the main admin invite from `enable-auth` lives 24
  hours. An invite is single use: `consume_invite` marks it used in the join transaction
  ([0008](0008-board-isolation-and-credentials.md)).
- **Revocation** is by id (`token revoke <id>`, `members remove`, board archive, and with the
  server stopped `stigmerd admin revoke-token <id>` for any credential, the instance token
  included, or `stigmerd admin new-instance-token --revoke-others` to replace the instance token)
  and takes effect on the next request; there is no cache. An events wait already in progress
  re-checks its credential (stored, not revoked, not expired, still a member) at every wake, so
  it ends with the same 401 instead of returning events
  ([0011](0011-authentication-policy-401-403-404.md)).

## Consequences

- A token can be found in logs or repositories by its prefix, and the CLI rejects a malformed
  `STIGMER_TOKEN` before sending anything.
- The id is the primary key, so finding and checking a credential costs one keyed read and one
  sha256 whether or not the id exists (a valid board token then needs a membership read and a
  last-seen write). The database time for a present versus an absent id is not equalised; ids
  are not secret, so this can reveal only which ids exist, not any secret.
- Rotation is "issue new, revoke old" (for the instance token, `new-instance-token
  --revoke-others` does both at once). There is no refresh flow and no automatic renewal: a
  90-day token simply stops working, and the holder joins again with a fresh invite.
- A future format (for example narrowed tokens in M4) takes a new prefix version (`stg2_`) and
  must keep accepting `stg1_` until those tokens expire.

## Amendments

First ships in v0.2.0, so it was amended in place during M1; after v0.2.0 ships it is frozen.

- 2026-11-22: `issue-member-token` is listed among the commands that show a secret once.
- 2026-11-22 (M1 final review): revocation by `revoke-token` and `new-instance-token --revoke-others`; an events wait re-checks its credential at every wake.
