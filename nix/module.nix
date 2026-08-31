# NixOS module for the tmite daemon: run `tmite daemon` as a systemd
# service and put `tmite` in environment.systemPackages so `tmite code`,
# `tmite list`, and `tmite cancel` can talk to it over its Unix socket.
#
# The daemon terminates iroh streams and forwards to plain TCP, so it sees
# the tunneled traffic; only run it on a host you trust. The socket is
# deliberately left at the daemon default (0666): any local user can create
# sessions, but the pairing code and SAS still authenticate.
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
      environment.systemPackages. The daemon listens on a Unix socket
      (default /run/tmite/daemon) and manages one-shot pairing sessions
      over iroh.

      Prerequisites:
      - At least one allow-forward pattern (see allowForward)
    '';

    package = lib.mkPackageOption pkgs "tmite" { };

    allowForward = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "localhost:*" "*.internal:22" ];
      description = ''
        Glob patterns for allowed forward targets, matched against the
        full host:port string. Required: the daemon refuses to start
        without at least one pattern.
      '';
    };

    socket = lib.mkOption {
      type = lib.types.str;
      default = "/run/tmite/daemon";
      description = ''
        Unix socket the daemon listens on. The tmite CLI defaults to the
        same path, so this only needs to change if you also set TMITE_SOCKET
        for clients.
      '';
    };

    sessionTimeout = lib.mkOption {
      type = lib.types.str;
      default = "5m";
      description = "Session lifetime without a client.";
    };

    relays = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "wss://relay.example.com" ];
      description = ''
        Custom iroh relay URLs to use instead of the default n0
        production relays.
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
    assertions = [
      {
        assertion = cfg.allowForward != [ ];
        message = "tmite requires at least one allow-forward pattern: services.tmite.allowForward";
      }
    ];

    environment.systemPackages = [ cfg.package ];

    systemd.services.tmite = {
      description = "tmite daemon";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      serviceConfig = {
        Type = "simple";
        Restart = "on-failure";
        RuntimeDirectory = "tmite";
      };
      script =
        "${cfg.package}/bin/tmite daemon"
        + " --listen ${lib.escapeShellArg cfg.socket}"
        + " --session-timeout ${lib.escapeShellArg cfg.sessionTimeout}"
        + lib.concatMapStrings (p: " --allow-forward ${lib.escapeShellArg p}") cfg.allowForward
        + lib.concatMapStrings (r: " --relay ${lib.escapeShellArg r}") cfg.relays
        + lib.optionalString (cfg.pkarr != "") " --pkarr ${lib.escapeShellArg cfg.pkarr}";
    };
  };
}
