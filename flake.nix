{
  description = "A devShell example";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        libs = with pkgs; [ zstd elfutils libbpf bpftools zlib glibc ];
      in {
        devShells.default = with pkgs;
          mkShell {
            nativeBuildInputs = [ pkg-config elfutils ];
            buildInputs = [
              clang
              clang-tools
              openssl
              elfutils
              rust-bin.stable.latest.default
            ] ++ libs;

          };
      });
}
