//! The database URL: the TLS settings stigmerd reads out of it (`sslmode` and `sslrootcert`,
//! which the driver cannot take), and what it says about its target. Nothing here returns or
//! prints the password; an error message has every form of it removed.

use std::net::IpAddr;

use tokio_postgres::config::Host;

/// A database URL with its TLS settings taken out.
pub(crate) struct ParsedUrl {
    /// The URL as written, minus `sslmode` and `sslrootcert`: what the store connects with.
    pub(crate) url: String,
    /// The `sslmode` value, if the URL had one.
    pub(crate) sslmode: Option<String>,
    /// The `sslrootcert` value (a file path), if the URL had one.
    pub(crate) sslrootcert: Option<String>,
    /// Whether the URL carries a password (in the user info or as a parameter).
    pub(crate) has_password: bool,
    /// Whether every host it names is this machine: a loopback address, `localhost` or a Unix
    /// socket directory. A URL with no host is not.
    pub(crate) loopback: bool,
    /// `database <db> on <host>:<port>`, without user or password.
    pub(crate) target: String,
}

/// Reads `raw`, a `postgres://` URL or a key-value connection string.
pub(crate) fn parse(raw: &str) -> Result<ParsedUrl, String> {
    let split = split_tls(raw)?;
    let config: tokio_postgres::Config = split.rest.parse().map_err(|e| {
        let message = format!("invalid database URL: {e}");
        split
            .passwords
            .iter()
            .fold(message, |text, secret| text.replace(secret, "***"))
    })?;
    Ok(ParsedUrl {
        has_password: config.get_password().is_some(),
        loopback: loopback(&config),
        target: target(&config),
        url: split.rest,
        sslmode: split.sslmode,
        sslrootcert: split.sslrootcert,
    })
}

/// A connection string split into its TLS parameters and the rest, plus every form of a
/// password found on the way (for redaction).
struct Split {
    rest: String,
    sslmode: Option<String>,
    sslrootcert: Option<String>,
    passwords: Vec<String>,
}

/// Parameters stigmerd takes out of the connection string.
const TLS_KEYS: [&str; 2] = ["sslmode", "sslrootcert"];

/// Splits `raw`, refusing what the driver would read wrongly: an unencoded '@' in the user info
/// (part of the password would become the host, and show in messages) and a TLS parameter
/// given twice. The refusals never quote the URL.
fn split_tls(raw: &str) -> Result<Split, String> {
    let mut split = Split {
        rest: String::new(),
        sslmode: None,
        sslrootcert: None,
        passwords: Vec::new(),
    };
    let Some(after_scheme) = ["postgres://", "postgresql://"]
        .iter()
        .find_map(|scheme| raw.strip_prefix(scheme))
    else {
        // Key-value form: `key = value` pairs, values bare (backslash escapes) or quoted.
        let mut kept = Vec::new();
        for pair in key_values(raw) {
            if pair.key == "password" {
                split.passwords.push(pair.value.clone());
                split.passwords.push(pair.raw.to_owned());
            }
            if TLS_KEYS.contains(&pair.key) {
                take(&mut split, pair.key, pair.value)?;
            } else {
                kept.push(pair.raw);
            }
        }
        split.rest = kept.join(" ");
        split.passwords.retain(|p| !p.is_empty());
        return Ok(split);
    };
    let scheme_len = raw.len() - after_scheme.len();
    // As the driver reads it: the user info runs to the FIRST '@', the parameters start at the
    // first '?' after it.
    let creds_end = after_scheme.find('@');
    if let Some(end) = creds_end {
        // What the driver takes for the host list: up to the path or the parameters.
        let hosts = after_scheme[end + 1..]
            .split(['/', '?'])
            .next()
            .unwrap_or("");
        if hosts.contains('@') {
            return Err(
                "the database URL has more than one '@' before its path: percent-encode '@' in \
                 the user name or password as %40 (the URL is not shown)"
                    .into(),
            );
        }
        if let Some((_, password)) = after_scheme[..end].split_once(':') {
            split.passwords.push(password.to_owned());
            split.passwords.push(percent_decode(password));
        }
    }
    let search_from = creds_end.map_or(0, |end| end + 1);
    let Some(query_at) = after_scheme[search_from..]
        .find('?')
        .map(|i| scheme_len + search_from + i)
    else {
        split.rest = raw.to_owned();
        split.passwords.retain(|p| !p.is_empty());
        return Ok(split);
    };
    let mut kept = Vec::new();
    for param in raw[query_at + 1..].split('&') {
        let (key, value) = param.split_once('=').unwrap_or((param, ""));
        let key = percent_decode(key);
        if key == "password" {
            split.passwords.push(value.to_owned());
            split.passwords.push(percent_decode(value));
        }
        if TLS_KEYS.contains(&key.as_str()) {
            take(&mut split, &key, percent_decode(value))?;
        } else {
            kept.push(param);
        }
    }
    split.rest = if kept.is_empty() {
        raw[..query_at].to_owned()
    } else {
        format!("{}?{}", &raw[..query_at], kept.join("&"))
    };
    split.passwords.retain(|p| !p.is_empty());
    Ok(split)
}

/// Keeps the value of the TLS parameter `key`; a second one is refused rather than letting
/// either win silently.
fn take(split: &mut Split, key: &str, value: String) -> Result<(), String> {
    let slot = match key {
        "sslmode" => &mut split.sslmode,
        _ => &mut split.sslrootcert,
    };
    if slot.is_some() {
        return Err(format!(
            "{key} is given more than once in the database URL; give it once"
        ));
    }
    *slot = Some(value);
    Ok(())
}

/// One `key = value` of a key-value connection string: its key, its unescaped value and the
/// text it was written as.
struct Pair<'a> {
    key: &'a str,
    value: String,
    raw: &'a str,
}

/// The pairs of a key-value connection string, read as the driver reads them. Text that is not
/// a well-formed pair is kept whole as one last "pair" with an empty key, so the driver still
/// sees (and reports) it.
fn key_values(raw: &str) -> Vec<Pair<'_>> {
    let mut pairs = Vec::new();
    let bytes: Vec<(usize, char)> = raw.char_indices().collect();
    let len = bytes.len();
    let offset = |i: usize| bytes.get(i).map_or(raw.len(), |(o, _)| *o);
    let mut i = 0;
    while i < len {
        while i < len && bytes[i].1.is_whitespace() {
            i += 1;
        }
        if i >= len {
            break;
        }
        let start = i;
        while i < len && !bytes[i].1.is_whitespace() && bytes[i].1 != '=' {
            i += 1;
        }
        let key = &raw[offset(start)..offset(i)];
        while i < len && bytes[i].1.is_whitespace() {
            i += 1;
        }
        if key.is_empty() || i >= len || bytes[i].1 != '=' {
            pairs.push(Pair {
                key: "",
                value: String::new(),
                raw: &raw[offset(start)..],
            });
            return pairs;
        }
        i += 1;
        while i < len && bytes[i].1.is_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        let quoted = i < len && bytes[i].1 == '\'';
        if quoted {
            i += 1;
        }
        while i < len {
            let c = bytes[i].1;
            if (quoted && c == '\'') || (!quoted && c.is_whitespace()) {
                break;
            }
            i += 1;
            if c == '\\' {
                if let Some((_, next)) = bytes.get(i) {
                    value.push(*next);
                    i += 1;
                }
            } else {
                value.push(c);
            }
        }
        if quoted && i < len {
            i += 1; // the closing quote
        }
        pairs.push(Pair {
            key,
            value,
            raw: &raw[offset(start)..offset(i)],
        });
    }
    pairs
}

/// Decodes `%XX` escapes; anything else is kept as written.
fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escaped = bytes
            .get(i + 1..i + 3)
            .filter(|_| bytes[i] == b'%')
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match escaped {
            Some(byte) => {
                out.push(byte);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// True when every address the connection may go to is on this machine. With `hostaddr` those
/// are the addresses; otherwise the hosts.
fn loopback(config: &tokio_postgres::Config) -> bool {
    let addrs = config.get_hostaddrs();
    if !addrs.is_empty() {
        return addrs.iter().all(IpAddr::is_loopback);
    }
    let hosts = config.get_hosts();
    !hosts.is_empty()
        && hosts.iter().all(|host| match host {
            Host::Tcp(name) => {
                let name = name.trim_end_matches('.');
                name.eq_ignore_ascii_case("localhost")
                    || name
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .parse::<IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            }
            #[cfg(unix)]
            Host::Unix(_) => true,
        })
}

/// `database <db> on <host>:<port>`, as the store names its target.
fn target(config: &tokio_postgres::Config) -> String {
    let hosts: Vec<String> = config
        .get_hosts()
        .iter()
        .map(|host| match host {
            Host::Tcp(name) => name.clone(),
            #[cfg(unix)]
            Host::Unix(path) => path.display().to_string(),
        })
        .collect();
    let port = config.get_ports().first().copied().unwrap_or(5432);
    let database = config.get_dbname().or(config.get_user()).unwrap_or("?");
    format!("database {database} on {}:{port}", hosts.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_parameters_are_taken_out_of_a_url_and_the_rest_kept_in_order() {
        let parsed = parse(
            "postgres://u@db.example:5433/app?application_name=a&sslmode=verify-full\
             &connect_timeout=5&sslrootcert=%2Fetc%2Fca.pem",
        )
        .unwrap();
        assert_eq!(
            parsed.url,
            "postgres://u@db.example:5433/app?application_name=a&connect_timeout=5"
        );
        assert_eq!(parsed.sslmode.as_deref(), Some("verify-full"));
        assert_eq!(parsed.sslrootcert.as_deref(), Some("/etc/ca.pem"));
        assert_eq!(parsed.target, "database app on db.example:5433");

        let only_tls = parse("postgresql://db.example/app?sslmode=require").unwrap();
        assert_eq!(only_tls.url, "postgresql://db.example/app");
        assert_eq!(only_tls.sslmode.as_deref(), Some("require"));

        let none = parse("postgres://db.example/app").unwrap();
        assert_eq!(none.url, "postgres://db.example/app");
        assert_eq!((none.sslmode, none.sslrootcert), (None, None));
    }

    #[test]
    fn a_question_mark_in_the_password_does_not_start_the_parameters() {
        let parsed = parse("postgres://u:pa?ss@db.example/app?sslmode=require").unwrap();
        assert_eq!(parsed.url, "postgres://u:pa?ss@db.example/app");
        assert_eq!(parsed.sslmode.as_deref(), Some("require"));
        assert!(parsed.has_password);
    }

    #[test]
    fn tls_parameters_are_taken_out_of_a_key_value_string() {
        let parsed = parse(
            "host=db.example sslmode = verify-full dbname='my app' sslrootcert='/a b/ca.pem' \
             user=u",
        )
        .unwrap();
        assert_eq!(parsed.url, "host=db.example dbname='my app' user=u");
        assert_eq!(parsed.sslmode.as_deref(), Some("verify-full"));
        assert_eq!(parsed.sslrootcert.as_deref(), Some("/a b/ca.pem"));
        assert_eq!(parsed.target, "database my app on db.example:5432");
        assert!(!parsed.has_password);
    }

    #[test]
    fn a_password_is_found_in_every_form() {
        for url in [
            "postgres://u:secret@db.example/app",
            "postgres://u:s%40cret@db.example/app",
            "postgres://u@db.example/app?password=secret",
            "host=db.example user=u password=secret",
            "host=db.example user=u password='se cret'",
        ] {
            assert!(parse(url).unwrap().has_password, "{url}");
        }
        for url in ["postgres://u@db.example/app", "host=db.example user=u"] {
            assert!(!parse(url).unwrap().has_password, "{url}");
        }
    }

    #[test]
    fn parse_errors_never_show_the_password() {
        for (url, secret) in [
            ("postgres://u:hunter2@db.example:notaport/app", "hunter2"),
            ("postgres://u:hun%74er2@db.example/app?hunter2=1", "hunter2"),
            (
                "postgres://u@db.example/app?password=hunter2&nonsense=1",
                "hunter2",
            ),
            ("host=db.example password=hunter2 nonsense=1", "hunter2"),
            ("host=db.example password='hunter 2' bogus", "hunter 2"),
            ("postgres://u:p@ssw0rdX@127.0.0.1:1/db", "ssw0rdX"),
            ("postgres://u:a/b@ssw0rdX@127.0.0.1:1/db", "ssw0rdX"),
        ] {
            let err = parse(url)
                .err()
                .unwrap_or_else(|| panic!("{url} is refused"));
            assert!(
                err.starts_with("invalid database URL") || err.contains("percent-encode"),
                "{err}"
            );
            assert!(!err.contains(secret), "{url}: {err}");
        }
    }

    #[test]
    fn loopback_means_every_host_is_this_machine() {
        for url in [
            "postgres://localhost/app",
            "postgres://LOCALHOST./app",
            "postgres://127.0.0.1:5433/app",
            "postgres://[::1]/app",
            "postgres://localhost,127.0.0.2/app",
            "postgres://%2Ftmp/app",
            "host=/var/run/postgresql dbname=app",
            "postgres://db.example/app?hostaddr=127.0.0.1",
        ] {
            assert!(parse(url).unwrap().loopback, "{url}");
        }
        for url in [
            "postgres://db.example/app",
            "postgres://localhost,db.example/app",
            "postgres://10.0.0.1/app",
            "postgres://localhost/app?hostaddr=10.0.0.1",
            "postgres:///app",
        ] {
            assert!(!parse(url).unwrap().loopback, "{url}");
        }
    }

    #[test]
    fn a_tls_parameter_given_twice_is_refused() {
        for url in [
            "postgres://db.example/app?sslmode=require&sslmode=disable",
            "postgres://db.example/app?sslrootcert=a.pem&sslrootcert=b.pem",
            "host=db.example sslmode=require sslmode=disable",
        ] {
            let err = parse(url)
                .err()
                .unwrap_or_else(|| panic!("{url} is refused"));
            assert!(err.contains("more than once"), "{url}: {err}");
        }
    }

    #[test]
    fn an_at_sign_after_the_host_is_not_mistaken_for_a_second_one() {
        let parsed = parse("postgres://u@db.example/app?application_name=a@b").unwrap();
        assert_eq!(parsed.target, "database app on db.example:5432");
    }
}
