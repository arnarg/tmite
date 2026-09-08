# NixOS module for the tmite daemon: run `tmite daemon` as the system user
# and group `tmite` via a systemd service and put `tmite` in
# environment.systemPackages so the admin CLI (`tmite peer ...`,
# `tmite status`) can talk to it over its IPC socket and clients can run
# `tmite pair` / `tmite connect`.
#
# State (keypair, peers, ACL rules) lives in /var/lib/tmite and persists
# across restarts. The daemon binds its IPC socket mode 0660, so users in
# the `tmite` group can administer it without root, matching the
# docker.sock trust model from the design doc.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.tmite;
in
{
  options.services.tmite = {
    enable = lib.mkEnableOption ''
      the tmite daemon.

      Runs `tmite daemon` as a systemd service and adds `tmite` to
      environment.systemPackages. The daemon holds the server's persistent
      iroh identity in /var/lib/tmite, serves the admin CLI on a Unix
      socket (default /run/tmite/daemon.sock, mode 0660), and accepts
      forwarded TCP traffic from paired peers over iroh.

      The daemon runs as the system user and group `tmite`; users added to
      the `tmite` group can use the admin CLI without root.

      Peers are paired and granted access with the admin CLI, e.g.
      `sudo tmite peer invite --name laptop` and
      `sudo tmite peer allow laptop localhost:22`.
    '';

    package = lib.mkPackageOption pkgs "tmite" { };

    dataDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/tmite";
      description = ''
        Directory for the daemon's keypair and persisted state
        (`state.toml`), passed as `--data-dir`. Backed by the systemd
        StateDirectory `tmite`.
      '';
    };

    socket = lib.mkOption {
      type = lib.types.str;
      default = "/run/tmite/daemon.sock";
      description = ''
        Unix socket the daemon serves the admin CLI on, passed as
        `--socket-path`. The tmite CLI defaults to the same path, so this
        only needs to change if you also set --socket-path for admin
        clients. The daemon forces the socket to mode 0660, so users in the
        daemon service's group can run admin commands.
      '';
    };

    idleTimeout = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 0;
      example = 300;
      description = ''
        Per-stream idle timeout in seconds for forwarded data-plane
        streams, passed as `--idle-timeout`. 0 (the default) disables the
        timeout.
      '';
    };

    relays = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "wss://relay.example.com" ];
      description = ''
        Custom iroh relay URLs to use instead of the default n0
        production relays. Repeatable; setting any replaces the n0 relay
        map entirely.
      '';
    };

    pkarr = lib.mkOption {
      type = lib.types.str;
      default = "";
      example = "https://pkarr.example.com/pkarr";
      description = ''
        Custom pkarr HTTP relay URL for publishing the daemon's
        addressing. Empty uses the n0 production pkarr relay.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    users.groups.tmite = { };
    users.users.tmite = {
      isSystemUser = true;
      group = "tmite";
      description = "tmite tunnel daemon";
    };

    systemd.services.tmite = {
      description = "tmite tunnel daemon";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      serviceConfig = {
        Type = "simple";
        Restart = "on-failure";
        User = "tmite";
        Group = "tmite";
        RuntimeDirectory = "tmite";
        StateDirectory = "tmite";
      };
      script =
        "${cfg.package}/bin/tmite daemon"
        + " --data-dir ${lib.escapeShellArg cfg.dataDir}"
        + " --socket-path ${lib.escapeShellArg cfg.socket}"
        + lib.optionalString (cfg.idleTimeout != 0) " --idle-timeout ${toString cfg.idleTimeout}"
        + lib.concatMapStrings (r: " --relay ${lib.escapeShellArg r}") cfg.relays
        + lib.optionalString (cfg.pkarr != "") " --pkarr ${lib.escapeShellArg cfg.pkarr}";
    };
  };
}
