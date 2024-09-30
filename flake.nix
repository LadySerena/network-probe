{
  description = "A devShell example";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils = { url = "github:numtide/flake-utils"; };
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
            # stack protection nor zerocallusedregs support bpf targets 
            hardeningDisable = [ "stackprotector" "zerocallusedregs" ];
            buildInputs =
              [ clang openssl elfutils rust-bin.stable.latest.default ] ++ libs;

          };
      });
}
