FROM rust:1-bookworm AS chef 
ENV DEBIAN_FRONTEND=noninteractive
RUN rustup component add rustfmt
RUN curl -LO https://github.com/coord-e/magicpak/releases/download/v1.4.0/magicpak-x86_64-unknown-linux-musl --output-dir /usr/bin/ && mv /usr/bin/magicpak-x86_64-unknown-linux-musl /usr/bin/magicpak && chmod +x /usr/bin/magicpak
RUN apt-get update && apt-get install pkgconf zlib1g-dev libelf-dev protobuf-compiler bpftool build-essential clang -y
RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .
COPY ../container-meta .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin "network-probe"
RUN /usr/bin/magicpak -v /app/target/release/network-probe /app/bundle
FROM scratch
COPY --from=builder /app/target/release/network-probe /
COPY --from=builder /app/bundle /.
ENTRYPOINT ["/network-probe"]
