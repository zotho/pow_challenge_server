# PoW challenge HTTP server

Setup:
```console
docker network create pow
docker build -t pow_challenge_server_http:latest .
```

Server:
```console
// server <JWT_EXPIRE_SECONDS> <ZERO_COUNT>
docker run \
    --env RUST_LOG=INFO \
    --rm \
    --init \
    -it \
    --net pow \
    --name pow_server \
    pow_challenge_server_http:latest \
    /usr/local/bin/server 5 5
```

Client:
```console
// client <SERVER_HOSTNAME:PORT> <N_CLIENTS>
docker run \
    --env RUST_LOG=INFO,client=DEBUG \
    --rm \
    --init \
    -it \
    --net pow \
    pow_challenge_server_http:latest \
    /usr/local/bin/client pow_server:3000 10
```

If you want to recreate recipe.json for Docker.
```
cargo chef prepare --recipe-path recipe.json
```
See: https://github.com/LukeMathWalker/cargo-chef

## SHA-256
SHA-256 was chosen as the PoW algorithm because it is quite difficult to crack but easy to verify the results. The same algorithm is used in the Hashcash system.

Reference: https://en.wikipedia.org/wiki/Hashcash