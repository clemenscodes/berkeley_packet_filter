{
  cargo-nextest,
  mkShell,
  rustToolchain,
}:
mkShell {
  name = "berkeley_packet_filter";

  packages = [
    cargo-nextest
    rustToolchain
  ];

  CARGO_TERM_COLOR = "always";

  RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
}
