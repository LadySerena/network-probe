FROM rust:1 as build-env
WORKDIR /app
COPY . /app/
RUN cargo build --release --bin "client"

FROM gcr.io/distroless/cc-debian12
COPY --from=build-env /app/target/release/client /
CMD ["./client"]
