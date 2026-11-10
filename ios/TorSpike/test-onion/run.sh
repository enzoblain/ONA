#!/bin/sh
# Test .onion server for the Tor spike, run on the Mac with C Tor (brew install tor).
# Serves a one-line page over an onion service. Ctrl-C stops both processes.
#
# The onion service key stays outside the repository, in $ONA_TEST_ONION_DIR
# (default: ~/Library/Application Support/ona-test-onion). Delete that folder to get a new address.
set -eu

DATA="${ONA_TEST_ONION_DIR:-$HOME/Library/Application Support/ona-test-onion}"
HTTP_PORT="${ONA_TEST_HTTP_PORT:-8088}"
mkdir -p "$DATA/www" "$DATA/tor"
mkdir -p -m 700 "$DATA/hs"
chmod 700 "$DATA/tor" "$DATA/hs"
echo "ONA tor spike: onion reached" > "$DATA/www/index.html"

python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 --directory "$DATA/www" &
HTTP_PID=$!
trap 'kill $HTTP_PID 2>/dev/null' EXIT INT TERM

cat > "$DATA/torrc" <<TORRC
SocksPort 0
DataDirectory $DATA/tor
HiddenServiceDir $DATA/hs
HiddenServicePort 80 127.0.0.1:$HTTP_PORT
Log notice stdout
TORRC

( while [ ! -s "$DATA/hs/hostname" ]; do sleep 1; done
  echo "==> Onion address: $(cat "$DATA/hs/hostname")" ) &

tor --version | head -1
tor -f "$DATA/torrc"
