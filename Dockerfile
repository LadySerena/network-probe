FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
RUN rustup component add rustfmt
RUN curl -LO https://github.com/coord-e/magicpak/releases/download/v1.4.0/magicpak-x86_64-unknown-linux-musl --output-dir /usr/bin/ && mv /usr/bin/magicpak-x86_64-unknown-linux-musl /usr/bin/magicpak && chmod +x /usr/bin/magicpak
RUN apt-get update && apt-get install pkgconf zlib1g-dev libelf-dev protobuf-compiler bpftool build-essential clang -y
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# build deps
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
# build app
RUN cargo build --release --bin "network-probe"
RUN /usr/bin/magicpak -v /app/target/release/network-probe /app/bundle
FROM scratch
COPY --from=builder /app/bundle /.
ENTRYPOINT ["/app/target/release/network-probe"]
