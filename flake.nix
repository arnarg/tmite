{
  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-26.05";
  inputs.gomod2nix.url = "github:nix-community/gomod2nix";
  inputs.gomod2nix.inputs.nixpkgs.follows = "nixpkgs";
  inputs.microvm.url = "github:microvm-nix/microvm.nix";
  inputs.microvm.inputs.nixpkgs.follows = "nixpkgs";

  outputs =
    {
      self,
      nixpkgs,
      gomod2nix,
      microvm,
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
    in
    {
      packages = forAllSystems (
        system: pkgs: {
          default = self.packages.${system}.tmite;
          tmite = pkgs.callPackage ./package.nix {
            inherit (gomod2nix.legacyPackages.${system}) buildGoApplication;
          };
        }
        # Runner for the test VM (build with `nix build .#vm`).
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          vm = self.nixosConfigurations.tmite-test.config.microvm.declaredRunner;
        }
      );

      apps = forAllSystems (
        system: pkgs: {
          gomod2nix = {
            type = "app";
            program = "${gomod2nix.legacyPackages.${system}.gomod2nix}/bin/gomod2nix";
          };
        }
        # `nix run .#vm` boots the test VM in this terminal.
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          vm = {
            type = "app";
            program = "${self.nixosConfigurations.tmite-test.config.microvm.declaredRunner}/bin/microvm-run";
          };
        }
      );

      devShells = forAllSystems (
        system: pkgs: {
          default = pkgs.mkShellNoCC {
            buildInputs = [
              gomod2nix.legacyPackages.${system}.gomod2nix
            ];
          };
        }
      );

      # nix/module.nix stays a plain module (default `pkgs.tmite`); this
      # wrapper defaults the package to the flake build, so importing the
      # module and enabling is enough.
      nixosModules.default =
        {
          lib,
          pkgs,
          ...
        }:
        {
          imports = [ ./nix/module.nix ];
          services.tmite.package = lib.mkDefault (self.packages.${pkgs.stdenv.hostPlatform.system}.tmite);
        };

      # Test VM with the tmite daemon and openssh; boot with `nix run .#vm`.
      nixosConfigurations.tmite-test = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          microvm.nixosModules.microvm
          self.nixosModules.default
          ./nix/vm/configuration.nix
          {
            services.tmite.enable = true;
            services.tmite.allowForward = [ "localhost:*" ];
          }
        ];
      };
    };
}
