//! Resolution of default data and socket directories (§3, §9).

use std::path::{Path, PathBuf};

use tmite_core::fsio::candidate_socket_paths_with;

#[test]
fn explicit_socket_path_short_circuits() {
    let explicit = Path::new("/custom/sock");
    assert_eq!(
        candidate_socket_paths_with(Some(explicit), Some(Path::new("/run/user/1000/tmite"))),
        vec![explicit.to_path_buf()]
    );
}

#[test]
fn candidates_prefer_user_runtime_then_system() {
    assert_eq!(
        candidate_socket_paths_with(None, Some(Path::new("/run/user/1000/tmite"))),
        vec![
            PathBuf::from("/run/user/1000/tmite/daemon.sock"),
            PathBuf::from("/run/tmite/daemon.sock"),
        ]
    );
}

#[test]
fn candidates_fall_back_to_system_runtime() {
    assert_eq!(
        candidate_socket_paths_with(None, None),
        vec![PathBuf::from("/run/tmite/daemon.sock")]
    );
}
