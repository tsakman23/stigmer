//! map-local-principals: turning board main's local authors into members.

use stigmer_core::{BoardId, Principal, PrincipalKind, Role};
use stigmer_store::{Adoption, ConflictKind, IdentityStore, StoreError};

use super::{store_failure, INSTANCE_ADMIN};
use crate::Failure;

/// The `map-local-principals` name flags, as given.
pub(super) struct MappedNames<'a> {
    pub(super) humans: &'a [String],
    pub(super) admins: &'a [String],
    pub(super) skips: &'a [String],
}

/// Plans, and with `apply` performs, the adoption of board main's local authors.
pub(super) async fn map_local_principals<S: IdentityStore>(
    store: &S,
    now: i64,
    names: MappedNames<'_>,
    apply: bool,
) -> Result<String, Failure> {
    let main = BoardId::main();
    let authors = store
        .list_local_authors(&main)
        .await
        .map_err(|e| store_failure("cannot list local authors", &e))?;
    if authors.is_empty() {
        return Ok("nothing to map\n".into());
    }
    let humans = known_authors(names.humans, &authors, "--human")?;
    let admins = known_authors(names.admins, &authors, "--admin")?;
    let skips = known_authors(names.skips, &authors, "--skip")?;
    if let Some(both) = admins.iter().find(|name| skips.contains(name)) {
        return Err(Failure::Config(format!(
            "--admin {both} is also --skip; an admin must be adopted"
        )));
    }
    if admins.is_empty() {
        return Err(Failure::Config(
            "at least one --admin is required so the board keeps an administrator".into(),
        ));
    }
    // A reserved name can never be a member: refuse before planning, so the plan never lists it.
    if let Some(reserved) = authors
        .iter()
        .find(|name| name.as_str() == INSTANCE_ADMIN && !skips.contains(name))
    {
        return Err(Failure::Config(format!(
            "local author \"{reserved}\" uses a reserved name; rerun with --skip {reserved} \
             (its messages stay local)"
        )));
    }
    let adoptions: Vec<Adoption> = authors
        .iter()
        .filter(|name| !skips.contains(name))
        .map(|name| Adoption {
            name: name.clone(),
            kind: if humans.contains(name) {
                PrincipalKind::Human
            } else {
                PrincipalKind::Agent
            },
            role: if admins.contains(name) {
                Role::Admin
            } else {
                Role::Member
            },
        })
        .collect();
    if !apply {
        let mut text = plan_table(&adoptions);
        text.push_str("dry run: nothing changed; rerun with --apply to write this mapping\n");
        return Ok(text);
    }
    let messages = match store.adopt_local_authors(&main, &adoptions, now).await {
        Ok(messages) => messages,
        Err(StoreError::Conflict(ConflictKind::NameTaken)) => {
            return Err(name_taken(store, &main, &adoptions).await)
        }
        Err(e) => return Err(store_failure("cannot map local principals", &e)),
    };
    Ok(format!(
        "adopted {} authors and {messages} messages into board main\n",
        adoptions.len()
    ))
}

/// The failure for an adoption refused as `NameTaken`, naming the first author that is already
/// a member when one can be found.
async fn name_taken<S: IdentityStore>(
    store: &S,
    board: &BoardId,
    adoptions: &[Adoption],
) -> Failure {
    for adoption in adoptions {
        if let Ok(Some(_)) = store.get_member(board, &adoption.name).await {
            let name = &adoption.name;
            return Failure::Runtime(format!(
                "cannot map local principals: local author \"{name}\" is already a member of \
                 board {board}; rerun with --skip {name}"
            ));
        }
    }
    store_failure(
        "cannot map local principals",
        &StoreError::Conflict(ConflictKind::NameTaken),
    )
}

/// Parses `names` and checks each is one of the local `authors`.
fn known_authors(
    names: &[String],
    authors: &[Principal],
    flag: &str,
) -> Result<Vec<Principal>, Failure> {
    names
        .iter()
        .map(|raw| {
            let name =
                Principal::new(raw).map_err(|e| Failure::Config(format!("{flag} {raw:?}: {e}")))?;
            if authors.contains(&name) {
                Ok(name)
            } else {
                let known: Vec<&str> = authors.iter().map(Principal::as_str).collect();
                Err(Failure::Config(format!(
                    "{flag} {raw}: not a local author of main (authors: {})",
                    known.join(", ")
                )))
            }
        })
        .collect()
}

fn plan_table(adoptions: &[Adoption]) -> String {
    let width = adoptions
        .iter()
        .map(|a| a.name.as_str().len())
        .chain([4])
        .max()
        .unwrap_or(4);
    let mut text = format!("{:<width$}  {:<5}  ROLE\n", "NAME", "KIND");
    for a in adoptions {
        text.push_str(&format!(
            "{:<width$}  {:<5}  {}\n",
            a.name.as_str(),
            a.kind.as_str(),
            a.role.as_str()
        ));
    }
    text
}
