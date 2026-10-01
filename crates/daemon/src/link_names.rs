//! Deterministic, kernel-safe tunnel link names. Pure string logic shared by
//! the platform-neutral request planners and the Linux executors.

fn link_name_seed(uid: u32, profile_id: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in uid.to_le_bytes().iter().chain(profile_id.as_bytes()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Sanitize a caller-supplied hint into a lowercase kernel-safe slug: ASCII
/// alphanumerics are kept, every other character collapses into a single `-`.
fn link_name_slug(hint: &str, budget: usize) -> Option<String> {
    let mut slug = String::with_capacity(budget.min(hint.len()));
    for ch in hint.chars().flat_map(char::to_lowercase) {
        if slug.len() >= budget {
            break;
        }
        if ch.is_ascii_alphanumeric() {
            slug.push(ch);
        } else if !(slug.is_empty() || slug.ends_with('-')) {
            slug.push('-');
        }
    }
    let slug = slug.trim_end_matches('-');
    (!slug.is_empty()).then(|| slug.to_string())
}

/// Resolve the kernel interface name and a collision fallback. The hint is
/// preferred verbatim when it already reads as a prefixed name ("wg-kzn2",
/// "wg0"), else it gets the prefix ("kzn2" -> "wg-kzn2"). When the hint is
/// missing or unusable, the deterministic hash name is used for both slots.
/// All results fit IFNAMSIZ-1 (15) bytes of pure ASCII.
pub(crate) fn tunnel_link_names(
    prefix: &str,
    uid: u32,
    profile_id: &str,
    hint: Option<&str>,
) -> (String, String) {
    const MAX_LEN: usize = 15;
    let hex_digits = MAX_LEN - prefix.len();
    let seed = link_name_seed(uid, profile_id);
    let hashed = format!(
        "{prefix}{:0width$x}",
        seed & ((1u64 << (4 * hex_digits)) - 1),
        width = hex_digits
    );
    let Some(slug) = hint.and_then(|hint| link_name_slug(hint, MAX_LEN)) else {
        return (hashed.clone(), hashed);
    };
    let bare = prefix.trim_end_matches('-');
    if slug == bare {
        return (hashed.clone(), hashed);
    }
    // The hint is used verbatim when it already carries our prefix
    // ("wg-kzn2") or is a "<bare><digits>" name like "wg0"; otherwise it is
    // slugged under the prefix ("KZN2 uplink" -> "wg-kzn2-uplink"). This also
    // keeps every result matching validators like `valid_tun_name`.
    let verbatim = slug.starts_with(prefix)
        || (slug.starts_with(bare)
            && slug.len() > bare.len()
            && slug.as_bytes()[bare.len()].is_ascii_digit());
    let primary = if verbatim {
        slug[..slug.len().min(MAX_LEN)].to_string()
    } else {
        let room = MAX_LEN - prefix.len();
        format!("{prefix}{}", &slug[..slug.len().min(room)])
    };
    let short = primary[..primary.len().min(MAX_LEN - 5)].trim_end_matches('-');
    let fallback = if short.len() <= prefix.len() {
        hashed.clone()
    } else {
        format!("{short}-{:04x}", seed & 0xffff)
    };
    (primary, fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_names_prefer_sanitized_hint() {
        let (name, fallback) = tunnel_link_names("wg-", 1000, "home", Some("KZN2 uplink"));
        assert_eq!(name, "wg-kzn2-uplink");
        assert!(fallback.starts_with("wg-kzn2-"));
        assert!(fallback.len() <= 15);
        assert_ne!(name, fallback);

        // Hints that already look like interface names stay verbatim.
        assert_eq!(
            tunnel_link_names("wg-", 1000, "home", Some("wg-kzn2")).0,
            "wg-kzn2"
        );
        assert_eq!(tunnel_link_names("wg-", 1000, "home", Some("wg0")).0, "wg0");

        let (name, fallback) = tunnel_link_names(
            "wg-",
            1000,
            "home",
            Some("a very long interface name indeed"),
        );
        assert!(name.len() <= 15);
        assert!(name.starts_with("wg-"));
        assert!(fallback.len() <= 15);
    }

    #[test]
    fn link_names_fall_back_to_deterministic_hash() {
        let (name, fallback) = tunnel_link_names("wg-", 1000, "home", None);
        assert_eq!(name, fallback);
        assert_eq!(name.len(), 15);
        assert!(name[3..].chars().all(|c| c.is_ascii_hexdigit()));
        // Empty or fully unsanitizable hints produce the same hash name.
        assert_eq!(name, tunnel_link_names("wg-", 1000, "home", Some("")).0);
        assert_eq!(name, tunnel_link_names("wg-", 1000, "home", Some("!!!")).0);
        assert_eq!(
            name,
            tunnel_link_names("wg-", 1000, "home", Some("🇳🇱 Нидерланды")).0
        );
        // Deterministic per (uid, profile_id).
        assert_ne!(name, tunnel_link_names("wg-", 1000, "other", None).0);
        assert_ne!(name, tunnel_link_names("wg-", 1001, "home", None).0);
    }
}
