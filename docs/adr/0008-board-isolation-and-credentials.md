# 0008. Board isolation and credentials

Status: Accepted, amended; partly superseded by [0014](0014-audit-rows-in-the-mutation-transaction.md)
Date: 2026-11-22

## Context

M1 puts several boards (teams or projects) on one server and lets people and agents reach them
over a network. A leaked credential must expose as little as possible, a board's existence and
content must not leak to anyone outside it, and someone has to create boards and mint the first
invites. The design considered instance-wide tokens with per-board roles in a table, and one token
per board plus a separate instance credential (design M1 section 5).

## Decision

- **One token per board.** A board credential (`CredentialScope::Board`) authorizes exactly one
  board. A person or agent on two boards holds two tokens; the CLI keeps one login per server
  and board. A board token comes from redeeming an invite (`stigmer join`), or, for an existing
  member (an adopted M0 author, or someone who lost a token), from the operator:
  `stigmerd admin issue-member-token --board <b> --member <name>` (server stopped, network mode,
  90 days by default, at most 365; refused on an archived board; logged as `member_token_issued`).
- **The instance credential** (`CredentialScope::Instance`, principal `instance-admin`, kind
  human) is not a board member. It is created by `stigmerd admin enable-auth` (90 days) or
  `stigmerd admin new-instance-token` (`--expires-days`, 1 to 365, default 90). Without
  `--revoke-others` the old token stays valid until it expires or is revoked; with it, every
  other instance token is revoked in the same store transaction that stores the new one
  (`IdentityStore::replace_instance_credential`), so a failure leaves the old token valid rather
  than no token at all. `stigmerd admin revoke-token <id>` revokes any credential, instance or
  board, by id (server stopped, network mode; an unknown id exits 2; a repeat revoke changes
  nothing; logged once as `token_revoked`, with the id only). It creates, lists and archives
  boards, lists members and tokens of any board, mints invites into any board and revokes any
  token, but `RoleAuthorize` never lets it read or post content: content routes answer it 403.
  The principal name `instance-admin` is reserved: no member may take it (`add_member`,
  `adopt_local_authors` and `consume_invite` refuse it as `Conflict(NameTaken)`), so the
  name in the security log always means the operator. `map-local-principals` refuses (exit 2)
  to plan or apply an adoption of a local author with that name and points at `--skip <name>`,
  which leaves an author and its messages local.
- **Roles per board** ([0004](0004-authorization-seam.md)): `admin` reads, posts and manages
  members, invites and tokens of its board and may archive it; `member` and `bridge` read and
  post. An invite binds board, role and kind; the bridge role and the bridge kind go together.
- **Archive** is one-way (no unarchive in M1). The handler archives the board first, then revokes
  every live credential on it except those of board admins. The order matters: once archived, the
  store refuses invites into the board, so the revoke step sees every credential there will ever
  be; revoking first would leave a window for a join to get a live token that is never revoked.
  Both steps are idempotent, so if the revoke fails (500) a retry completes it. Board admins keep
  read access; an archived board refuses posts, members, invites, credentials and joins
  (`Conflict(BoardArchived)`, wire code `board_archived`, HTTP 409). The store checks the
  archive before the idempotency key, so a keyed retry of a post that had already committed
  before the archive also gets 409 `board_archived`: that answer does not mean the original
  write failed (read the thread to check).
- **`main` cannot be archived.** `Store::archive_board` refuses it with
  `Conflict(BoardProtected)` ("the main board cannot be archived"; HTTP 409 `conflict` for the
  instance admin and a board admin of `main` alike, in both modes), so `main` always exists and
  always takes posts. Board names are `[a-z0-9._-]{1,64}` but never only dots: `.` and `..` are
  path segments, so `BoardId` refuses them (400, CLI exit 5).
- **Join is atomic in the store.** `IdentityStore::consume_invite` checks the invite, adds the
  member, stores the credential, marks the invite used and writes the `Join` security log row
  in one transaction (SQLite `BEGIN IMMEDIATE`). A taken name is 409 and leaves the invite
  unused; any failure leaves nothing behind.
- **Bootstrap.** `enable-auth` also mints one admin invite (kind human) into `main`, valid 24
  hours (`--no-main-invite` skips it). `map-local-principals` requires at least one `--admin`
  ([0007](0007-local-principals.md)); `adopt_local_authors` writes its `principals_adopted`
  security log row in the adoption's own transaction.

## Consequences

- A leaked agent token exposes one board. A leaked instance token exposes board metadata, member
  and token lists and the power to mint invites (and so, indirectly, content); it is printed
  once and should be kept offline.
- A board credential never learns whether another board exists: every route answers it the same
  404 for any other board name, existing or not, without asking the store
  ([0011](0011-authentication-policy-401-403-404.md)).
- Security log rows other than `Join` and `principals_adopted` are written after the mutation,
  best effort: if the write fails the mutation stands and a one-line warning (no secrets) goes
  to stderr. M2 should move them into the mutation's transaction.
- Two people sharing a name on different boards are unrelated principals; there is no
  cross-board identity until OIDC (M5).
- Per-channel grants (M4) narrow a board token; they do not change the one-board scope.

## Amendments

First ships in v0.2.0, so it was amended in place during M1; after v0.2.0 ships it is frozen.

- 2026-11-22: a board token can also come from `stigmerd admin issue-member-token` for an existing member.
- 2026-11-22 (M1 final review): `new-instance-token --revoke-others` and `revoke-token`; the name `instance-admin` is reserved; `main` cannot be archived; board names of dots only are refused; `principals_adopted` is logged in the adoption's transaction.
- 2026-11-22: `map-local-principals` refuses a local author named `instance-admin` and points at `--skip`.
