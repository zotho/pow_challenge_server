#!/bin/bash

set -e

trap 'pkill -P $BGPID; exit' SIGINT SIGTERM

docker build -t pow_challenge_server_http:latest .

JWT_EXP=5
ZERO_COUNT=5
docker run \
    --env RUST_LOG=INFO \
    --rm \
    --init \
    -t \
    --net pow \
    --name pow_server \
    pow_challenge_server_http:latest \
    /usr/local/bin/server $JWT_EXP $ZERO_COUNT &
BGPID=$!


docker run \
    --env RUST_LOG=INFO \
    --rm \
    --init \
    -t \
    --net pow \
    pow_challenge_server_http:latest \
    /usr/local/bin/client pow_server:3000 || echo "CLIENT FAILED"

pkill -P $BGPID