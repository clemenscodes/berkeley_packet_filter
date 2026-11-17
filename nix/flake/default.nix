{ inputs, ... }:
{
  systems = [ "x86_64-linux" ];

  perSystem =
    { system, ... }:
    let
      pkgs = import inputs.nixpkgs {
        inherit system;
        overlays = [ inputs.rust-overlay.overlays.default ];
      };

      rustToolchain = pkgs.callPackage ./packages/rustToolchain {
        pinned = ../../rust-toolchain.toml;
      };

      craneLib = (inputs.crane.mkLib pkgs).overrideToolchain rustToolchain;

      source = craneLib.cleanCargoSource inputs.self;

      berkeleyPacketFilter = pkgs.callPackage ./packages/berkeleyPacketFilter {
        inherit craneLib source;
      };

      devShell = pkgs.callPackage ./devShells/berkeleyPacketFilter {
        inherit rustToolchain;
      };
    in
    {
      _module.args = {
        inherit pkgs;
      };

      formatter = pkgs.nixfmt-tree;

      packages = {
        default = berkeleyPacketFilter;
        berkeleyPacketFilter = berkeleyPacketFilter;
      };

      devShells.default = devShell;

      checks.berkeleyPacketFilter = berkeleyPacketFilter;
    };
}
