{
  description = "Benzene privileged access service";

  outputs =
    args:
    let
      inputs = (import ./.tack) { overrides = args.tackOverrides or { }; };
      inherit (inputs) fenix nixpkgs;
      inherit (nixpkgs) lib;

      forAllSystems = lib.genAttrs lib.systems.doubles.linux;
      pkgsFor = system: nixpkgs.legacyPackages.${system} or (import nixpkgs { inherit system; });

      # Fenix only ships binaries for tier-1 arches, so fall back to nixpkgs's rustc
      # everywhere else.
      hasFenix = system: fenix.packages ? ${system};
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          toolchain =
            if hasFenix system then
              fenix.packages.${system}.complete.withComponents [
                "cargo"
                "clippy"
                "rust-analyzer"
                "rust-src"
                "rustc"
                "rustfmt"
              ]
            else
              pkgs.rustc;
        in
        {
          default = pkgs.mkShell {
            packages = [
              toolchain
              pkgs.nixfmt
              pkgs.taplo
            ];
          };
        }
      );

      formatter = forAllSystems (system: (pkgsFor system).nixfmt);
    };
}
