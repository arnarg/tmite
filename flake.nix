{
  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-26.05";
  inputs.gomod2nix.url = "github:nix-community/gomod2nix";
  inputs.gomod2nix.inputs.nixpkgs.follows = "nixpkgs";

  outputs =
    {
      self,
      nixpkgs,
      gomod2nix,
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
      );

      apps = forAllSystems (
        system: pkgs: {
          gomod2nix = {
            type = "app";
            program = "${gomod2nix.legacyPackages.${system}.gomod2nix}/bin/gomod2nix";
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
    };
}
