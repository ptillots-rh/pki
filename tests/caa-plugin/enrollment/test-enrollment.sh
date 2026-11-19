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
ADDITIONAL_DOMAINS=()
MODE=smoke
LOG_FILE=""
DIRECTORY=https://pki.example.com:8443/acme/directory
CAA_CONFIG=/etc/pki/pki-tomcat/acme/caa.conf
WEB_LIB=/usr/share/pki/acme/webapps/acme/WEB-INF/lib
RUN_DIR=""
DNS_PID=""
VALIDATOR_PID=""
CONFIG_CHANGED=false

# Describe host prerequisites and the deliberate service/policy changes before execution.
usage() {
    cat <<'HELP'
Usage: test-enrollment.sh [--caa]
                          [--instance NAME] [--directory-url URL]
                          [--domain NAME] [--additional-domain NAME] [--ca-cert FILE] [--log FILE]
                          [--upgrade-check]

Run on a disposable PKI test host with CA and ACME already configured.
Default: use Certbot HTTP-01 to obtain and verify one certificate.
--caa: test issuance with signed allow/deny, bogus signatures, authenticated
       insecurity, signed alias/absence and resolver outage scenarios.
       Uses BIND authority on loopback 1054 and validating Unbound on 1053.
       Requires BIND/signing tools, Unbound, dig and the installed dnsjava adapter.
--instance: PKI instance name (default: pki-tomcat).
--directory-url: ACME HTTPS directory URL (default: https://pki.example.com:8443/acme/directory).
--ca-cert: CA trust PEM; otherwise export ca_signing from the selected instance.
--upgrade-check: test missing/preserved CAA config using the installed migration
                 and pki-server upgrade before enrollment; restores original policy.
--additional-domain: add a DNS SAN (repeatable).
CAA tests require a public baseURL in the ACME instance's engine.conf.
Configure it before testing; this harness does not change engine.conf.
Every name must resolve to this test host. Port 80 must be free.
This test temporarily changes CAA policy and restarts the selected service.
Certificates, private keys and logs are retained in a private /tmp directory.
HELP
}

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

# Check before changing policy or restarting ACME. Reuse PKI's property reader.
check_engine_config() {
    python3 - "$1" <<'PYTHON'
import sys
from urllib.parse import urlsplit

import pki.util

filename = sys.argv[1]
settings = {}
try:
    pki.util.load_properties(filename, settings)
except Exception:
    raise SystemExit(f'ERROR: Cannot read ACME engine configuration: {filename}')
value = settings.get('baseURL', '')
try:
    url = urlsplit(value)
    valid = (url.scheme in ('http', 'https') and url.hostname is not None
             and url.username is None and url.password is None
             and not any(c.isspace() for c in value)
             and (url.port is None or 1 <= url.port <= 65535))
except ValueError:
    valid = False
if not valid:
    raise SystemExit(f'ERROR: CAA requires a public HTTP(S) baseURL in {filename}; '
                     'configure it and restart ACME before testing')
PYTHON
}

while (( $# )); do
    case "$1" in
        --upgrade-check) UPGRADE_CHECK=true; shift ;;
        --caa) MODE=caa; shift ;;
        --domain|--additional-domain|--log|--instance|--directory-url|--ca-cert)
            (( $# >= 2 )) || fail "Missing value for $1"
            case "$1" in
                --instance) INSTANCE="$2" ;;
                --directory-url) DIRECTORY="$2" ;;
                --ca-cert) CA_CERT="$2" ;;
                --domain) DOMAIN="$2" ;;
                --additional-domain) ADDITIONAL_DOMAINS+=("$2") ;;
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
CERTIFICATE_NAMES=("${DOMAIN,,}")
for name in "${ADDITIONAL_DOMAINS[@]}"; do
    CERTIFICATE_NAMES+=("${name,,}")
done
CERTBOT_NAMES=()
for name in "${CERTIFICATE_NAMES[@]}"; do
    [[ "$name" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ && "$name" == *.* ]] || fail "Use DNS hostnames without wildcards or trailing dots"
    CERTBOT_NAMES+=(-d "$name")
done
DOMAIN="${CERTIFICATE_NAMES[0]}"
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
[[ -s "/etc/pki/$INSTANCE/acme/database.conf" ]] || fail "Configure a disposable CA-backed ACME instance first"
if [[ "$MODE" != smoke ]]; then
    check_engine_config "/etc/pki/$INSTANCE/acme/engine.conf"
    for tool in named unbound dig dnssec-keygen dnssec-signzone dnssec-dsfromkey; do
        command -v "$tool" >/dev/null || fail "DNSSEC fixtures need $tool"
    done
    for name in "${CERTIFICATE_NAMES[@]}"; do
        [[ "$name" =~ ^[a-z0-9-]+\.example\.com$ ]] ||
            fail "The private DNS fixture requires single-label names under example.com"
    done
    [[ -r "$CAA_CONFIG" && -f "$CAA_CONFIG" && ! -L "$CAA_CONFIG" ]] ||
        fail "Tests require a readable regular CAA policy file (no symlink): $CAA_CONFIG"
    jar tf /usr/share/java/pki/pki-acme.jar | grep -Fx 'org/dogtagpki/acme/caa/CAAIssuanceGate.class' >/dev/null || fail "Installed ACME JAR lacks CAA support"
    [[ -r "$WEB_LIB/pki-acme-dnsjava.jar" ]] || fail "Install ACME with --with-acme-dnsjava before running --caa (Maven tests alone do not deploy it)"
fi

# Certbot serves HTTP-01 on the test host identified by DOMAIN.
python3 - "${CERTIFICATE_NAMES[@]}" <<'PY'
import socket
import sys
for name in sys.argv[1:]:
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

# Reap fixture processes with bounded shutdown, including unsuccessful startup attempts.
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

# Require a trusted HTTPS directory with the endpoints needed by the test client.
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

# Restore policy and service readiness on every exit while preserving a failing test status.
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

# Keep each scenario in a separate account/client directory so previous certificates cannot count as success.
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
        "${CERTBOT_NAMES[@]}" 9>&- > "$RUN_DIR/$scenario/client.log" 2>&1
}

# Verify the final CA output, including exact names and possession of the matching private key.
verify_certificate() {
    local scenario="$1" cert_dir="$RUN_DIR/$1/config/live/caa-enrollment-test"
    openssl verify -CAfile "$RUN_DIR/ca.pem" -untrusted "$cert_dir/chain.pem" "$cert_dir/cert.pem"
    openssl x509 -in "$cert_dir/cert.pem" -noout -checkhost "$DOMAIN"
    python3 "$SCRIPT_DIR/verify_certificate_names.py" "$cert_dir/cert.pem" "${CERTIFICATE_NAMES[@]}"
    openssl x509 -in "$cert_dir/cert.pem" -pubkey -noout > "$RUN_DIR/$scenario/cert-public.pem"
    openssl pkey -in "$cert_dir/privkey.pem" -pubout > "$RUN_DIR/$scenario/key-public.pem"
    cmp "$RUN_DIR/$scenario/cert-public.pem" "$RUN_DIR/$scenario/key-public.pem"
    openssl x509 -in "$cert_dir/cert.pem" -noout -serial -issuer -dates
    echo "PASS: $scenario issued a trusted certificate with the requested SAN and matching key"
}

# Require both client success and independently retrieved persisted order/certificate state.
expect_success() {
    local scenario="$1"
    echo "Testing $scenario enrollment..."
    if ! run_certbot "$scenario"; then
        tail -40 "$RUN_DIR/$scenario/client.log"
        fail "$scenario enrollment failed; see $RUN_DIR/$scenario/logs/letsencrypt.log"
    fi
    verify_certificate "$scenario"
    python3 "$SCRIPT_DIR/verify_order.py" "$RUN_DIR/$scenario" "$DIRECTORY" valid
}

# Distinguish an ordinary ACME rejection from a timeout, crash or certificate issued despite failure.
expect_rejection() {
    local scenario="$1" error="$2" status=0
    echo "Testing $scenario rejection..."
    run_certbot "$scenario" || status=$?
    [[ "$status" != 0 && "$status" != 124 && "$status" != 137 ]] || fail "$scenario did not return an ordinary ACME rejection (exit $status)"
    [[ ! -e "$RUN_DIR/$scenario/config/live/caa-enrollment-test/cert.pem" ]] || fail "$scenario unexpectedly produced a certificate"
    grep -F "urn:ietf:params:acme:error:$error" "$RUN_DIR/$scenario/logs/letsencrypt.log" >/dev/null || fail "$scenario failed for another reason; see its client/debug logs"
    python3 "$SCRIPT_DIR/verify_order.py" "$RUN_DIR/$scenario" "$DIRECTORY" invalid --error "$error"
    echo "PASS: $scenario returned ACME $error, persisted an invalid order and produced no certificate"
}

# Check resolver readiness separately from enrollment. The fixture's signed
# parent establishes insecurity; an AD-clear reply alone is not that proof.
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

# Generate private DNS data and require working authority and validation before enrollment.
start_dnssec() {
    local scenario="$1" denied_name="${2:-}" name attempt expected=secure ready=false
    local generation_args=()
    [[ "$scenario" != insecure ]] || expected=insecure
    [[ "$scenario" != bogus ]] || expected=bogus
    stop_dns
    for name in "${ADDITIONAL_DOMAINS[@]}"; do
        generation_args+=(--additional-domain "${name,,}")
    done
    if [[ -n "$denied_name" ]]; then
        generation_args+=(--denied-domain "$denied_name")
    fi
    python3 "$SCRIPT_DIR/../src/test/resources/dnssec_fixture.py" --directory "$RUN_DIR/dnssec" \
        --domain "$DOMAIN" --scenario "$scenario" "${generation_args[@]}" > "$RUN_DIR/$scenario-signing.log" 2>&1 ||
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

# Reload the adapter between scenario data changes. This clears resolver/client
# state and makes each enrollment use the policy written for that scenario.
configure_caa() {
    CONFIG_CHANGED=true
    cat > "$CAA_CONFIG" <<CONFIG
# Temporary DNSSEC test policy. Restored by test-enrollment.sh on exit.
enabled=true
issuerIdentifiers=ca.example.com
dns.class=org.dogtagpki.acme.caa.dnsjava.DNSJavaCAAProvider
dns.settings.server=127.0.0.1
dns.settings.port=1053
CONFIG
    systemctl restart "pki-tomcatd@$INSTANCE" 9>&- >> "$RUN_DIR/restart.log" 2>&1
    wait_for_acme || fail "ACME did not start with the delegated DNSSEC provider"
}

# Exercise the complete CAA/DNSSEC policy path through installed enrollment.
run_caa_tests() {
    [[ -e "$RUN_DIR/caa.conf.original" ]] || cp -a "$CAA_CONFIG" "$RUN_DIR/caa.conf.original"
    for scenario in secure-allow secure-deny bogus insecure alias-negative; do
        start_dnssec "$scenario"
        # Restart between scenarios to avoid cached data or stale connections.
        # The generated hierarchy reuses the same fixture keys for this run.
        configure_caa
        case "$scenario" in
            secure-deny) expect_rejection "$scenario" caa ;;
            bogus) expect_rejection "$scenario" dns ;;
            *) expect_success "$scenario" ;;
        esac
    done

    # A grant for one SAN must not hide a denial for another requested name.
    if (( ${#CERTIFICATE_NAMES[@]} > 1 )); then
        start_dnssec secure-allow "${CERTIFICATE_NAMES[1]}"
        configure_caa
        expect_rejection one-name-denied caa
    fi

    stop_dns
    expect_rejection dns-unavailable dns
}

if [[ "$UPGRADE_CHECK" == true ]]; then
    [[ "$MODE" != smoke ]] || fail "Use --upgrade-check with --caa"
    cp -a "$CAA_CONFIG" "$RUN_DIR/caa.conf.original"
    CONFIG_CHANGED=true
    python3 "$SCRIPT_DIR/../upgrade/check_installed_upgrade.py" "$INSTANCE" > "$RUN_DIR/upgrade.log" 2>&1
    systemctl restart "pki-tomcatd@$INSTANCE" 9>&- >> "$RUN_DIR/upgrade.log" 2>&1
    wait_for_acme || fail "ACME did not start after upgrade verification"
fi

if [[ "$MODE" == smoke ]]; then
    # Keep the administrator's current CAA policy intact in the smoke test.
    expect_success smoke
else
    run_caa_tests
fi

echo "ACME feature checks passed ($MODE). This does not qualify renewal or public-trust deployment."
