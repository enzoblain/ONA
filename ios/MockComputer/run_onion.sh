#!/bin/sh
# Step 4: the mock computer reachable only through Tor, as an onion service (C Tor, `brew install tor`).
# The phone pairs with a QR that holds the .onion address and talks to the mock over Tor (Arti in the app).
# Ctrl-C stops both. The onion key stays outside the repository, in $ONA_MOCK_ONION_DIR
# (default: ~/Library/Application Support/ona-mock-onion). Delete that folder to get a new address.
set -eu
cd "$(dirname "$0")"

DATA="${ONA_MOCK_ONION_DIR:-$HOME/Library/Application Support/ona-mock-onion}"
PORT="${ONA_MOCK_PORT:-8790}"
mkdir -p "$DATA/tor"
mkdir -p -m 700 "$DATA/hs"
chmod 700 "$DATA/tor" "$DATA/hs"

cat > "$DATA/torrc" <<TORRC
SocksPort 0
DataDirectory $DATA/tor
HiddenServiceDir $DATA/hs
HiddenServicePort 80 127.0.0.1:$PORT
Log notice stdout
TORRC

tor --version | head -1
tor -f "$DATA/torrc" &
TOR_PID=$!
trap 'kill $TOR_PID 2>/dev/null' EXIT INT TERM

while [ ! -s "$DATA/hs/hostname" ]; do sleep 1; done
ONION=$(cat "$DATA/hs/hostname")
echo "==> Onion service: $ONION (port 80 -> 127.0.0.1:$PORT)"

# Listens on localhost only: the phone can reach it through Tor, not through the local network.
python3 mock_computer.py --host 127.0.0.1 --port "$PORT" --onion "$ONION" "$@"
