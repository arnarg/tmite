//! Unit tests for daemon state (§14.1 ACL matching, persistence).

use tmite_core::daemon::state::{Peer, State};

fn new_state(name: &str) -> (tempfile::TempDir, State) {
    let dir = tempfile::TempDir::new().unwrap();
    let state = State::load(&dir.path().join(format!("{name}.toml"))).unwrap();
    state
        .add_peer(Peer {
            name: "laptop".into(),
            node_id: "aa11".into(),
            paired_at: "t".into(),
            last_seen: "t".into(),
        })
        .unwrap();
    (dir, state)
}

#[test]
fn acl_exact_string_match() {
    let (_d, state) = new_state("acl");
    state.add_rule("laptop", "localhost:22").unwrap();
    assert!(state.rule_allows("laptop", "localhost:22"));
    assert!(!state.rule_allows("laptop", "localhost:2222"));
    assert!(
        !state.rule_allows("laptop", "LOCALHOST:22"),
        "case-sensitive"
    );
    assert!(
        !state.rule_allows("laptop", "localhost:22 "),
        "trailing space"
    );
    assert!(!state.rule_allows("other", "localhost:22"));
}

#[test]
fn peer_without_rules_denies_everything() {
    let (_d, state) = new_state("no_rules");
    assert!(!state.rule_allows("laptop", "localhost:22"));
}

#[test]
fn rm_requires_force_when_rules_exist() {
    let (_d, state) = new_state("rm_force");
    state.add_rule("laptop", "localhost:22").unwrap();
    assert!(matches!(
        state.remove_peer("laptop", false),
        Err(tmite_core::daemon::state::StateError::PeerHasRules(_))
    ));
    assert!(state.remove_peer("laptop", true).unwrap());
    assert!(state.peer_by_name("laptop").is_none());
    assert!(
        !state.rule_allows("laptop", "localhost:22"),
        "rules cascade"
    );
}

#[test]
fn state_persists_across_reload() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("state.toml");
    {
        let state = State::load(&path).unwrap();
        state
            .add_peer(Peer {
                name: "laptop".into(),
                node_id: "aa11".into(),
                paired_at: "2026-09-07T12:00:00Z".into(),
                last_seen: "2026-09-07T12:00:00Z".into(),
            })
            .unwrap();
        state.add_rule("laptop", "localhost:22").unwrap();
    }
    let reloaded = State::load(&path).unwrap();
    assert!(reloaded.rule_allows("laptop", "localhost:22"));
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("[[peers]]"));
    assert!(text.contains("localhost:22"));
    assert!(!text.contains("invites"), "invites are runtime-only");
}

#[test]
fn duplicate_names_rejected_atomically() {
    let (_d, state) = new_state("dup");
    let second = state.add_peer(Peer {
        name: "laptop".into(),
        node_id: "bb22".into(),
        paired_at: "t".into(),
        last_seen: "t".into(),
    });
    assert!(matches!(
        second,
        Err(tmite_core::daemon::state::StateError::NameTaken(_))
    ));
}
