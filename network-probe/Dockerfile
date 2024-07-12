FROM rust:1-bookworm AS build-env
ENV DEBIAN_FRONTEND=noninteractive
RUN rustup component add rustfmt
RUN curl -LO https://github.com/coord-e/magicpak/releases/download/v1.4.0/magicpak-x86_64-unknown-linux-musl --output-dir /usr/bin/ && mv /usr/bin/magicpak-x86_64-unknown-linux-musl /usr/bin/magicpak && chmod +x /usr/bin/magicpak
RUN apt-get update && apt-get install pkgconf zlib1g-dev libelf-dev protobuf-compiler bpftool build-essential clang -y
WORKDIR /app
COPY . /app/
RUN cargo build --release --bin "network-probe"
RUN /usr/bin/magicpak -v /app/target/release/network-probe /app/bundle
FROM scratch
COPY --from=build-env /app/target/release/network-probe /
COPY --from=build-env /app/bundle /.
ENTRYPOINT ["/network-probe"]
