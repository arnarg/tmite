use tmite_core::fsio::{ClientStore, FsError, ServerEntry};

fn entry(name: &str, node_id: &str) -> ServerEntry {
    ServerEntry {
        name: name.to_string(),
        node_id: node_id.to_string(),
        paired_at: "2026-09-07T12:00:00Z".to_string(),
    }
}

#[test]
fn load_missing_file_returns_empty_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("servers.toml");
    let store = ClientStore::load(&path).unwrap();
    assert_eq!(store.version, 1);
    assert!(store.servers.is_empty());
}

#[test]
fn save_and_load_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("servers.toml");

    let mut store = ClientStore::load(&path).unwrap();
    store.upsert(entry("mybox", "aaaa")).unwrap();
    store.upsert(entry("vps", "bbbb")).unwrap();
    store.save(&path).unwrap();

    let loaded = ClientStore::load(&path).unwrap();
    assert_eq!(loaded.servers.len(), 2);
    assert_eq!(loaded.get("mybox").unwrap().node_id, "aaaa");
    assert_eq!(loaded.get("vps").unwrap().node_id, "bbbb");
    assert!(loaded.get("nope").is_none());
}

#[test]
fn save_is_atomic_no_tmp_leftover() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("servers.toml");

    let mut store = ClientStore::load(&path).unwrap();
    store.upsert(entry("mybox", "aaaa")).unwrap();
    store.save(&path).unwrap();

    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(entries, vec!["servers.toml".to_string()]);
}

#[test]
fn repair_same_server_replaces_entry() {
    let mut store = ClientStore::default();
    store.upsert(entry("old-name", "aaaa")).unwrap();
    store.upsert(entry("new-name", "aaaa")).unwrap();

    assert_eq!(store.servers.len(), 1);
    assert!(store.get("old-name").is_none());
    assert_eq!(store.get("new-name").unwrap().node_id, "aaaa");
}

#[test]
fn second_server_cannot_steal_existing_name() {
    let mut store = ClientStore::default();
    store.upsert(entry("mybox", "aaaa")).unwrap();

    let err = store.upsert(entry("mybox", "bbbb")).unwrap_err();
    assert!(matches!(err, FsError::NameInUse(ref n) if n == "mybox"));
    assert_eq!(store.servers.len(), 1);
    assert_eq!(store.get("mybox").unwrap().node_id, "aaaa");
}

#[test]
fn rename_onto_other_server_name_is_rejected() {
    let mut store = ClientStore::default();
    store.upsert(entry("foo", "aaaa")).unwrap();
    store.upsert(entry("bar", "bbbb")).unwrap();

    let err = store.upsert(entry("bar", "aaaa")).unwrap_err();
    assert!(matches!(err, FsError::NameInUse(ref n) if n == "bar"));
    assert_eq!(store.get("foo").unwrap().node_id, "aaaa");
    assert_eq!(store.get("bar").unwrap().node_id, "bbbb");
}

#[test]
fn multiple_servers_coexist_and_lookup_by_node() {
    let mut store = ClientStore::default();
    store.upsert(entry("laptop", "aaaa")).unwrap();
    store.upsert(entry("homelab", "bbbb")).unwrap();
    store.upsert(entry("vps", "cccc")).unwrap();

    assert_eq!(store.servers.len(), 3);
    assert_eq!(store.get_by_node_id("bbbb").unwrap().name, "homelab");
    assert!(store.get_by_node_id("dddd").is_none());
}
