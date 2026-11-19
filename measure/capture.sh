#!/bin/sh
# Ask the Compose hierarchy with dig and delv, and record what comes back.
#
#   measure/capture.sh hospital > measure/results/capture-hospital.txt
#   measure/capture.sh pouch    > measure/results/capture-pouch.txt
#
# Run from the repository root on a Linux Docker host with BIND's dig and delv
# installed: they run on the host and send queries straight to the containers'
# addresses, which Docker Desktop on macOS and Windows does not route to.
# No Python is needed on the host. The script brings the hierarchy up, asks the
# resolver and the emblem server for the emblem over UDP (EDNS payload 1232) and
# over TCP, asks delv to validate it against the root key in the zone files
# (which uses this host's clock, so it succeeds only within about two weeks of
# the example's date; see measure/README.md), and takes the hierarchy down again.
# DIEM_NET moves the hierarchy's addresses, as in compose.yaml.
set -e
example=${1:?usage: measure/capture.sh hospital|pouch}
case $example in hospital|pouch) ;; *) echo "unknown example: $example" >&2; exit 1 ;; esac
export DIEM_EXAMPLE=$example
net=${DIEM_NET:-10.53.0}
resolver=$net.53
emblem_server=$net.13

anchors=$(mktemp)
trap 'docker compose down --volumes >&2; rm -f "$anchors"' EXIT
docker compose up -d --build --wait >&2
name=$(docker compose run --rm --no-deps --entrypoint python generate \
  -c "from examples import $example; print($example.EMBLEM_NAME)")
docker compose exec -T resolver cat /zones/resolver/root.key \
  | awk '{ printf "trust-anchors { . initial-ds %s %s %s \"%s\"; };\n", $4, $5, $6, $7 }' > "$anchors"

echo "# Captures for $example: $name"
echo "# $(dig -v 2>&1), $(delv -v 2>&1)"
echo "# images: $(docker compose config --images | sort -u | tr '\n' ' ')"
echo "# $(date -u '+%Y-%m-%d %H:%M UTC')"
for where in "$resolver resolver" "$emblem_server emblem-server"; do
  set -- $where
  for transport in "+notcp" "+tcp"; do
    echo
    echo "## dig @$1 ($2) $transport"
    dig "@$1" "TYPE65280" "$name" +dnssec +bufsize=1232 +tries=1 $transport +ignore +noall +comments +stats \
      | grep -E 'flags|MSG SIZE|WARNING'
    dig "@$1" "TYPE65280" "$name" +dnssec +bufsize=1232 +tries=1 $transport +noall +answer \
      | awk '{print $1, $2, $3, $4, "..."}'
  done
done
echo
echo "## delv @$resolver validating against the root key"
delv "@$resolver" -a "$anchors" "$name" TYPE65280 +vtrace 2>&1 | grep -E 'fully validated|resolution failed|insecure|unsigned' | head -5
