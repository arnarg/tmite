{
  lib,
  buildGoApplication,
}:
let
  version = "0.1.0";
in
buildGoApplication {
  inherit version;
  pname = "tmite";

  src = builtins.filterSource (
    path: type:
    type == "directory"
    || baseNameOf path == "go.mod"
    || baseNameOf path == "go.sum"
    || lib.hasSuffix ".go" path
  ) ./.;

  modules = ./gomod2nix.toml;

  subPackages = [ "cmd/tmite" ];

  ldflags = [ "-X main.version=${version}" ];

  CGO_ENABLED = "0";

  meta = {
    mainProgram = "tmite";
  };
}
