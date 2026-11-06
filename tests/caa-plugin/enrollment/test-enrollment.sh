#!/usr/bin/env bash
# Exercise real ACME enrollment against a disposable, CA-backed PKI instance.
# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
# Security-sensitive: creates account/private keys and issues test certificates.
# --caa temporarily changes issuance policy; cleanup restores it and restarts PKI.
set -euo pipefail
umask 077
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTANCE=pki-tomcat
CA_CERT=""
UPGRADE_CHECK=false

DOMAIN=pki.example.com
MODE=smoke
PROVIDER=libunbound
LOG_FILE=""
DIRECTORY=https://pki.example.com:8443/acme/directory
CAA_CONFIG=/etc/pki/pki-tomcat/acme/caa.conf
WEB_LIB=/usr/share/pki/acme/webapps/acme/WEB-INF/lib
RUN_DIR=""
DNS_PID=""
VALIDATOR_PID=""
TRUST_ANCHOR=""
CONFIG_CHANGED=false

usage() {
    cat <<'HELP'
Usage: test-enrollment.sh [--caa|--dnssec] [--provider libunbound|dnsjava|dnsjava-local]
                          [--instance NAME] [--directory-url URL]
                          [--domain NAME] [--ca-cert FILE] [--log FILE]
                          [--upgrade-check]

Run on a disposable PKI test host with CA and ACME already configured.
Default: use Certbot HTTP-01 to obtain and verify one certificate.
--caa: test CAA allow, deny and DNS outage through actual ACME finalization.
       Requires the selected optional DNS adapter to be installed in ACME.
--dnssec: test local/delegated DNSSEC with a private signed DNS hierarchy.
          Uses BIND on loopback 1054 and a validating Unbound on 1053.
--provider dnsjava-local: use dnsjava's in-process validator; requires --dnssec.
--instance: PKI instance name (default: pki-tomcat).
--directory-url: ACME HTTPS directory URL (default: https://pki.example.com:8443/acme/directory).
--ca-cert: CA trust PEM; otherwise export ca_signing from the selected instance.
--upgrade-check: test missing/preserved CAA config using the installed migration
                 and pki-server upgrade before enrollment; restores original policy.
The domain must resolve to this test host. Port 80 must be free.
This test temporarily changes CAA policy and restarts the selected service.
Certificates, private keys and logs are retained in a private /tmp directory.
HELP
}

fail() { echo "ERROR: $*" >&2; exit 1; }

while (( $# )); do
    case "$1" in
        --upgrade-check) UPGRADE_CHECK=true; shift ;;
        --caa) MODE=caa; shift ;;
        --dnssec) MODE=dnssec; shift ;;
        --provider|--domain|--log|--instance|--directory-url|--ca-cert)
            (( $# >= 2 )) || fail "Missing value for $1"
            case "$1" in
                --instance) INSTANCE="$2" ;;
                --directory-url) DIRECTORY="$2" ;;
                --ca-cert) CA_CERT="$2" ;;
                --provider) PROVIDER="$2" ;;
                --domain) DOMAIN="$2" ;;
                --log) LOG_FILE="$2" ;;
            esac
            shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; fail "Unknown argument: $1" ;;
    esac
done
[[ "$INSTANCE" =~ ^[a-zA-Z0-9_-]+$ ]] || fail "Invalid instance name"
[[ "$DIRECTORY" == https://* ]] || fail "Use a trusted HTTPS directory URL"
CAA_CONFIG="/etc/pki/$INSTANCE/acme/caa.conf"
[[ "$PROVIDER" == libunbound || "$PROVIDER" == dnsjava || "$PROVIDER" == dnsjava-local ]] || fail "Unknown provider: $PROVIDER"
[[ "$PROVIDER" != dnsjava-local || "$MODE" == dnssec ]] || fail "dnsjava-local requires --dnssec"
ADAPTER="$PROVIDER"
[[ "$ADAPTER" != dnsjava-local ]] || ADAPTER=dnsjava
[[ "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ && "$DOMAIN" == *.* ]] || fail "Use a DNS hostname without a wildcard or trailing dot"
DOMAIN="${DOMAIN,,}"
(( EUID == 0 )) || fail "Run inside as root on the disposable test host (HTTP-01 uses port 80)"
if [[ -n "$LOG_FILE" ]]; then
    exec > >(tee -a "$LOG_FILE") 2>&1
fi

# Only one of these tests may own the HTTP listener and temporary CAA settings.
exec 9>/run/lock/pki-acme-caa-enrollment.lock
flock -n 9 || fail "Another ACME CAA enrollment test is running"

for tool in certbot openssl curl python3 timeout pki-server jar; do
    command -v "$tool" >/dev/null || fail "Missing test prerequisite: $tool"
done
[[ -s "/etc/pki/$INSTANCE/ca/CS.cfg" ]] || fail "Configure a disposable CA + ACME instance first"
if [[ "$MODE" != smoke ]]; then
    if [[ "$MODE" == caa ]]; then
        command -v dnsmasq >/dev/null && command -v dig >/dev/null || fail "CAA fixtures need dnsmasq and dig"
    else
        for tool in named unbound dig dnssec-keygen dnssec-signzone dnssec-dsfromkey; do
            command -v "$tool" >/dev/null || fail "DNSSEC fixtures need $tool"
        done
        [[ "$DOMAIN" =~ ^[a-z0-9-]+\.example\.com$ ]] || fail "DNSSEC fixture requires a single-label name under example.com"
    fi
    [[ -r "$CAA_CONFIG" && -f "$CAA_CONFIG" && ! -L "$CAA_CONFIG" ]] ||
        fail "Tests require a readable regular CAA policy file (no symlink): $CAA_CONFIG"
    jar tf /usr/share/java/pki/pki-acme.jar | grep -Fx 'org/dogtagpki/acme/caa/CAAIssuanceGate.class' >/dev/null || fail "Installed ACME JAR lacks CAA support"
    [[ -r "$WEB_LIB/pki-acme-$ADAPTER.jar" ]] || fail "Install ACME with --with-acme-$ADAPTER before running --caa (Maven tests alone do not deploy it)"
    if [[ "$PROVIDER" == libunbound ]]; then
        [[ -r /usr/lib64/libpki_acme_unbound.so || -r /usr/lib/libpki_acme_unbound.so ]] || fail "Install the libunbound JNI bridge"
        PROVIDER_CLASS=org.dogtagpki.acme.caa.libunbound.LibUnboundCAAProvider
    else
        PROVIDER_CLASS=org.dogtagpki.acme.caa.dnsjava.DNSJavaCAAProvider
    fi
    if [[ "$MODE" == dnssec ]]; then
        if [[ "$PROVIDER" != dnsjava ]]; then
            PROVIDER_CLASS+='$Validating'
        else
            PROVIDER_CLASS+='$LocalValidatingResolver'
        fi
    fi
fi

# Certbot serves HTTP-01 on the test host identified by DOMAIN.
python3 - "$DOMAIN" <<'PY'
import socket
import sys
name = sys.argv[1]
addresses = socket.getaddrinfo(name, 80, socket.AF_INET, socket.SOCK_STREAM)
for _, _, _, _, address in addresses:
    try:
        with socket.socket() as listener:
            listener.bind((address[0], 0))
        break
    except OSError:
        continue
else:
    raise SystemExit(f'{name} must resolve to an IPv4 address of this test host')
with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('0.0.0.0', 80))
PY

RUN_DIR="$(mktemp -d /tmp/pki-acme-test.XXXXXX)"
echo "ACME test: $MODE, domain: $DOMAIN"
echo "Results and private client state: $RUN_DIR"

stop_dns() {
    local attempt pid
    # Stop the validator first so its persistent upstream TCP closes as well.
    for pid in "${VALIDATOR_PID:-}" "$DNS_PID"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
            # A persistent TCP connection can delay a fixture's TERM handling.
            for attempt in {1..20}; do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.1
            done
            if kill -0 "$pid" 2>/dev/null; then
                kill -KILL "$pid" 2>/dev/null || true
            fi
            wait "$pid" 2>/dev/null || true
        fi
    done
    DNS_PID=""
    VALIDATOR_PID=""
}

wait_for_acme() {
    local attempt
    for attempt in {1..30}; do
        if curl --fail --silent --show-error --cacert "$RUN_DIR/ca.pem" \
                --connect-timeout 2 --max-time 5 "$DIRECTORY" \
                > "$RUN_DIR/directory.json" 2>/dev/null &&
                python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(not all(d.get(k) for k in ("newNonce","newAccount","newOrder","revokeCert")))' \
                < "$RUN_DIR/directory.json"; then
            return
        fi
        sleep 1
    done
    return 1
}

cleanup() {
    local status=$?
    trap - EXIT
    if [[ "$CONFIG_CHANGED" == true ]]; then
        echo "Restoring original CAA configuration and restarting PKI..."
        if ! cp -a "$RUN_DIR/caa.conf.original" "$CAA_CONFIG" ||
                ! systemctl restart "pki-tomcatd@$INSTANCE" 9>&- >> "$RUN_DIR/restore.log" 2>&1 ||
                ! wait_for_acme; then
            echo "ERROR: Restore/restart failed. Backup: $RUN_DIR/caa.conf.original" >&2
            status=1
        fi
    fi
    stop_dns
    if [[ -n "${TRUST_ANCHOR:-}" ]]; then
        rm -f -- "$TRUST_ANCHOR"
    fi
    echo "Results retained: $RUN_DIR"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Trust the private CA explicitly; do not disable Certbot's HTTPS verification.
if [[ -n "$CA_CERT" ]]; then
    cp -- "$CA_CERT" "$RUN_DIR/ca.pem"
else
    pki-server cert-export -i "$INSTANCE" --cert-file "$RUN_DIR/ca.pem" ca_signing > "$RUN_DIR/ca-export.log" 2>&1
fi
export REQUESTS_CA_BUNDLE="$RUN_DIR/ca.pem"
SERVER_HOST="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.urlparse(sys.argv[1]).hostname)' "$DIRECTORY")"
export NO_PROXY="$SERVER_HOST,$DOMAIN,127.0.0.1,localhost,${NO_PROXY:-}"
export no_proxy="$NO_PROXY"
wait_for_acme || fail "ACME directory is not ready or its TLS chain is not trusted"

run_certbot() {
    local scenario="$1"
    mkdir -p "$RUN_DIR/$scenario"
    : > "$RUN_DIR/$scenario/client.ini"
    timeout 180s certbot certonly --config "$RUN_DIR/$scenario/client.ini" \
        --server "$DIRECTORY" --standalone --preferred-challenges http \
        --key-type rsa --rsa-key-size 2048 --non-interactive --agree-tos \
        --email acme-test@example.com --no-directory-hooks \
        --config-dir "$RUN_DIR/$scenario/config" --work-dir "$RUN_DIR/$scenario/work" \
        --logs-dir "$RUN_DIR/$scenario/logs" --cert-name caa-enrollment-test \
        -d "$DOMAIN" 9>&- > "$RUN_DIR/$scenario/client.log" 2>&1
}

verify_certificate() {
    local scenario="$1" cert_dir="$RUN_DIR/$1/config/live/caa-enrollment-test"
    openssl verify -CAfile "$RUN_DIR/ca.pem" -untrusted "$cert_dir/chain.pem" "$cert_dir/cert.pem"
    openssl x509 -in "$cert_dir/cert.pem" -noout -checkhost "$DOMAIN"
    # Require a DNS SAN, rather than accepting only a matching common name.
    python3 - "$cert_dir/cert.pem" "$DOMAIN" <<'PY'
from cryptography import x509
from pathlib import Path
import sys
cert = x509.load_pem_x509_certificate(Path(sys.argv[1]).read_bytes())
names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
actual = set(names.get_values_for_type(x509.DNSName))
if actual != {sys.argv[2]}:
    raise SystemExit(f'Final DNS SANs differ from the checked name: {actual}')
cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
if cn and any(attribute.value != sys.argv[2] for attribute in cn):
    raise SystemExit('Profile introduced an unchecked common name')
PY
    openssl x509 -in "$cert_dir/cert.pem" -pubkey -noout > "$RUN_DIR/$scenario/cert-public.pem"
    openssl pkey -in "$cert_dir/privkey.pem" -pubout > "$RUN_DIR/$scenario/key-public.pem"
    cmp "$RUN_DIR/$scenario/cert-public.pem" "$RUN_DIR/$scenario/key-public.pem"
    openssl x509 -in "$cert_dir/cert.pem" -noout -serial -issuer -dates
    echo "PASS: $scenario issued a trusted certificate with the requested SAN and matching key"
}

expect_success() {
    local scenario="$1"
    echo "Testing $scenario enrollment..."
    if ! run_certbot "$scenario"; then
        tail -40 "$RUN_DIR/$scenario/client.log"
        fail "$scenario enrollment failed; see $RUN_DIR/$scenario/logs/letsencrypt.log"
    fi
    verify_certificate "$scenario"
    python3 "$SCRIPT_DIR/verify-order.py" "$RUN_DIR/$scenario" "$DIRECTORY" valid
}

expect_rejection() {
    local scenario="$1" error="$2" status=0
    echo "Testing $scenario rejection..."
    run_certbot "$scenario" || status=$?
    [[ "$status" != 0 && "$status" != 124 && "$status" != 137 ]] || fail "$scenario did not return an ordinary ACME rejection (exit $status)"
    [[ ! -e "$RUN_DIR/$scenario/config/live/caa-enrollment-test/cert.pem" ]] || fail "$scenario unexpectedly produced a certificate"
    grep -F "urn:ietf:params:acme:error:$error" "$RUN_DIR/$scenario/logs/letsencrypt.log" >/dev/null || fail "$scenario failed for another reason; see its client/debug logs"
    python3 "$SCRIPT_DIR/verify-order.py" "$RUN_DIR/$scenario" "$DIRECTORY" invalid --error "$error"
    echo "PASS: $scenario returned ACME $error, persisted an invalid order and produced no certificate"
}

start_dns() {
    local issuer="$1" answer attempt
    stop_dns
    dnsmasq --conf-file=/dev/null --no-daemon --no-resolv --no-hosts \
        --listen-address=127.0.0.1 --bind-interfaces --port=1053 \
        --cache-size=0 --local-ttl=60 --log-queries \
        --caa-record="$DOMAIN,0,issue,$issuer" \
        9>&- >> "$RUN_DIR/dns.log" 2>&1 &
    DNS_PID=$!
    for attempt in {1..20}; do
        kill -0 "$DNS_PID" 2>/dev/null || fail "DNS fixture exited; see $RUN_DIR/dns.log"
        answer="$(dig @127.0.0.1 -p 1053 "$DOMAIN" CAA +tcp +short +time=1 +tries=1 2>/dev/null)" || answer=""
        if [[ "$answer" == "0 issue \"$issuer\"" ]]; then
            return
        fi
        sleep 0.2
    done
    fail "DNS fixture did not return its configured CAA record"
}

dnssec_response_matches() {
    local file="$1" expected="$2"
    if [[ "$expected" == bogus ]]; then
        grep -F 'status: SERVFAIL,' "$file" >/dev/null
        return
    fi
    grep -F 'status: NOERROR,' "$file" >/dev/null || return 1
    if grep -E '^;; flags:([^;]* )?ad[ ;]' "$file" >/dev/null; then
        [[ "$expected" == secure ]]
    else
        [[ "$expected" == insecure ]]
    fi
}

start_dnssec() {
    local scenario="$1" attempt expected=secure ready=false
    [[ "$scenario" != insecure ]] || expected=insecure
    [[ "$scenario" != bogus ]] || expected=bogus
    stop_dns
    python3 "$SCRIPT_DIR/../dnssec/dnssec-fixture.py" --directory "$RUN_DIR/dnssec" \
        --domain "$DOMAIN" --scenario "$scenario" > "$RUN_DIR/$scenario-signing.log" 2>&1 ||
        fail "DNSSEC fixture generation failed; see $RUN_DIR/$scenario-signing.log"
    named -g -c "$RUN_DIR/dnssec/named.conf" -n 1 -U 1 \
        9>&- > "$RUN_DIR/$scenario-named.log" 2>&1 &
    DNS_PID=$!
    unbound -d -c "$RUN_DIR/dnssec/unbound.conf" \
        9>&- > "$RUN_DIR/$scenario-unbound.log" 2>&1 &
    VALIDATOR_PID=$!
    for attempt in {1..30}; do
        kill -0 "$DNS_PID" 2>/dev/null || fail "Authoritative fixture exited; see $RUN_DIR/$scenario-named.log"
        kill -0 "$VALIDATOR_PID" 2>/dev/null || fail "Validating resolver exited; see $RUN_DIR/$scenario-unbound.log"
        # Establish working authority and root trust before interpreting a
        # SERVFAIL or AD-clear result. A startup outage is not a bogus test.
        if dig @127.0.0.1 -p 1054 "$DOMAIN" CAA +tcp +dnssec +norecurse \
                +time=1 +tries=1 > "$RUN_DIR/$scenario-authority.txt" 2>/dev/null &&
                grep -F 'status: NOERROR,' "$RUN_DIR/$scenario-authority.txt" >/dev/null &&
                dig @127.0.0.1 -p 1053 . DNSKEY +tcp +dnssec +adflag \
                +time=1 +tries=1 > "$RUN_DIR/$scenario-root.txt" 2>/dev/null &&
                dnssec_response_matches "$RUN_DIR/$scenario-root.txt" secure &&
                dig @127.0.0.1 -p 1053 "$DOMAIN" CAA +tcp +dnssec +adflag \
                +time=1 +tries=1 > "$RUN_DIR/$scenario-probe.txt" 2>/dev/null &&
                dnssec_response_matches "$RUN_DIR/$scenario-probe.txt" "$expected"; then
            ready=true
            break
        fi
        sleep 0.2
    done
    [[ "$ready" == true ]] || fail "DNSSEC fixture did not establish $expected; see $RUN_DIR/$scenario-*.txt and resolver logs"
    echo "DNSSEC fixture verified: $scenario"
}

configure_dnssec() {
    local port=1053
    if [[ "$PROVIDER" != dnsjava ]]; then
        # Local validation queries the authoritative fixture, bypassing Unbound.
        port=1054
    fi
    CONFIG_CHANGED=true
    cat > "$CAA_CONFIG" <<CONFIG
# Temporary DNSSEC test policy. Restored by test-enrollment.sh on exit.
enabled=true
issuerIdentifiers=ca.example.com
dns.class=$PROVIDER_CLASS
dns.settings.server=127.0.0.1
dns.settings.port=$port
CONFIG
    if [[ "$PROVIDER" != dnsjava ]]; then
        if [[ -z "$TRUST_ANCHOR" ]]; then
            TRUST_ANCHOR="$(mktemp "${CAA_CONFIG%/*}/caa-test-anchor.XXXXXX")"
        fi
        cp "$RUN_DIR/dnssec/root.ds" "$TRUST_ANCHOR"
        chown --reference="$RUN_DIR/caa.conf.original" "$TRUST_ANCHOR"
        chmod 640 "$TRUST_ANCHOR"
        printf 'dns.settings.trustAnchors=%s\n' "$TRUST_ANCHOR" >> "$CAA_CONFIG"
    fi
    systemctl restart "pki-tomcatd@$INSTANCE" 9>&- >> "$RUN_DIR/restart.log" 2>&1
    wait_for_acme || fail "ACME did not start with the DNSSEC provider"
}

if [[ "$UPGRADE_CHECK" == true ]]; then
    [[ "$MODE" != smoke ]] || fail "Use --upgrade-check with --caa or --dnssec"
    cp -a "$CAA_CONFIG" "$RUN_DIR/caa.conf.original"
    CONFIG_CHANGED=true
    python3 "$SCRIPT_DIR/../upgrade/check-installed-upgrade.py" "$INSTANCE" > "$RUN_DIR/upgrade.log" 2>&1
    systemctl restart "pki-tomcatd@$INSTANCE" 9>&- >> "$RUN_DIR/upgrade.log" 2>&1
    wait_for_acme || fail "ACME did not start after upgrade verification"
fi

if [[ "$MODE" == smoke ]]; then
    # Keep the administrator's current CAA policy intact in the smoke test.
    expect_success smoke
elif [[ "$MODE" == caa ]]; then
    [[ -e "$RUN_DIR/caa.conf.original" ]] || cp -a "$CAA_CONFIG" "$RUN_DIR/caa.conf.original"
    start_dns ca.example.com
    CONFIG_CHANGED=true
    cat > "$CAA_CONFIG" <<CONFIG
# Temporary Phase 1 CAA test policy. Restored by test-enrollment.sh on exit.
enabled=true
issuerIdentifiers=ca.example.com
dns.class=$PROVIDER_CLASS
dns.settings.server=127.0.0.1
dns.settings.port=1053
CONFIG
    # Close the test lock in service-launcher children.
    systemctl restart "pki-tomcatd@$INSTANCE" 9>&- > "$RUN_DIR/restart.log" 2>&1
    wait_for_acme || fail "ACME did not start with the selected CAA adapter"
    expect_success caa-allow
    start_dns other-ca.example.com
    expect_rejection caa-deny caa
    stop_dns
    expect_rejection dns-unavailable dns
else
    [[ -e "$RUN_DIR/caa.conf.original" ]] || cp -a "$CAA_CONFIG" "$RUN_DIR/caa.conf.original"
    for scenario in secure-allow secure-deny bogus insecure alias-negative; do
        start_dnssec "$scenario"
        # Restart between scenarios to avoid cached data or stale connections.
        # The generated hierarchy reuses the same fixture keys for this run.
        configure_dnssec
        case "$scenario" in
            secure-deny) expect_rejection "$scenario" caa ;;
            bogus) expect_rejection "$scenario" dns ;;
            *) expect_success "$scenario" ;;
        esac
    done
    stop_dns
    expect_rejection dnssec-unavailable dns
fi

echo "ACME feature checks passed ($MODE). This does not qualify renewal or public-trust deployment."
