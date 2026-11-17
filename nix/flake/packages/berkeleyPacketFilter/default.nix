{
  cargo-nextest,
  craneLib,
  source,
}:
let
  crate = craneLib.crateNameFromCargoToml { cargoToml = "${source}/Cargo.toml"; };
in
craneLib.buildPackage {
  inherit (crate) pname version;
  src = source;
  strictDeps = true;
  doCheck = true;
  nativeBuildInputs = [ cargo-nextest ];
  cargoTestCommand = "cargo nextest run --cargo-profile release";
  env.NEXTEST_SHOW_PROGRESS = "counter";
}
