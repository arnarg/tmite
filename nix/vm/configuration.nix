# Test VM for tmite: a microvm.nix qemu guest running the tmite daemon
# and openssh. The daemon listens on /run/tmite/daemon; `tmite` is in
# environment.systemPackages so `tmite code` / `tmite list` work over SSH.
{
  ...
}:
{
  networking.hostName = "tmite-test";

  # microvm.nix: qemu, user-mode networking (SLiRP), direct kernel boot.
  microvm = {
    hypervisor = "qemu";
    interfaces = [
      {
        type = "user";
        id = "qemu";
        mac = "02:00:00:01:01:01";
      }
    ];
  };

  # SSH access to the guest so the daemon can be driven from the host.
  services.openssh = {
    enable = true;
    settings.PermitRootLogin = "yes";
  };

  users.users.root.initialPassword = "root";
  services.getty.autologinUser = "root";

  system.stateVersion = "26.05";
}
