{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
    }:
    let
      systems = nixpkgs.lib.systems.flakeExposed;
      forAllSystems =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f system (
            import nixpkgs {
              inherit system;
            }
          )
        );

      # The crate source: crane filters to the cargo-relevant files
      # (Cargo.toml, Cargo.lock, src/), so docs in this repo are
      # excluded from the build input.
      crateFor =
        pkgs:
        let
          craneLib = crane.mkLib pkgs;
          # Beyond the cargo-relevant files, the vectors/ JSON golden files
          # must be present: tmite-proto tests include_str! them at compile
          # time, so checks with --all-targets fail without them.
          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              (craneLib.fileset.commonCargoSources ./.)
              ./vectors
            ];
          };
          commonArgs = {
            inherit src;
            strictDeps = true;
          };
        in
        {
          inherit craneLib src commonArgs;
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
        };

      # Per-platform package build, following crane's workspace pattern: the
      # binary lives in the `tmite` member, built with a narrowed source
      # set. Native toolchain on every platform (dynamically linked).
      packageFor =
        pkgs:
        let
          crate = crateFor pkgs;
          craneLib = crate.craneLib;
          inherit (pkgs) lib;
          individualCrateArgs = crate.commonArgs // {
            inherit (crate) cargoArtifacts;
            inherit (craneLib.crateNameFromCargoToml { inherit (crate) src; }) version;
            doCheck = false;
          };
          # the tmite member depends on the other members, so the file set
          # unions all of their sources plus the workspace manifests
          fileSetForCrate =
            _crate:
            lib.fileset.toSource {
              root = ./.;
              fileset = lib.fileset.unions [
                ./Cargo.toml
                ./Cargo.lock
                (craneLib.fileset.commonCargoSources ./tmite-proto)
                (craneLib.fileset.commonCargoSources ./tmite-core)
                (craneLib.fileset.commonCargoSources ./tmite)
              ];
            };
        in
        craneLib.buildPackage (
          individualCrateArgs
          // {
            cargoExtraArgs = "-p tmite";
            src = fileSetForCrate ./tmite;
          }
        );

      # Compile-only checks reuse the cached cargoArtifacts; the test
      # suite runs via `cargo test` natively and in CI.
      checksFor =
        pkgs:
        let
          crate = crateFor pkgs;
        in
        {
          tmite-clippy = crate.craneLib.cargoClippy (
            crate.commonArgs
            // {
              inherit (crate) cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- --deny warnings";
            }
          );
          tmite-fmt = crate.craneLib.cargoFmt { inherit (crate) src; };
        };
    in
    {
      packages = forAllSystems (
        system: pkgs: {
          default = self.packages.${system}.tmite;
          tmite = packageFor pkgs;
        }
      );

      checks = forAllSystems (system: pkgs: checksFor pkgs);

      devShells = forAllSystems (
        system: pkgs: {
          default = pkgs.mkShell {
            # nixos-26.05 pins rustc 1.95, matching rust-toolchain.toml
            # and clearing iroh 1.1.0's MSRV (1.91).
            packages = with pkgs; [
              rustc
              cargo
              rustfmt
              clippy
            ];
          };
        }
      );
    };
}
