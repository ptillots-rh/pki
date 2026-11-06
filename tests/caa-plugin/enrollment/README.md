# Real ACME CAA enrollment tests

`test-enrollment.sh` exercises the actual servlet and configured CA issuer.
It temporarily changes issuance policy, restarts the selected PKI service,
creates ACME accounts/private keys and issues test certificates. Use a
disposable test instance, not a production CA. Security-sensitive changes
require extra review.

Prerequisites:

- An installed CA-backed ACME responder, configured database and realm, and
  the selected optional plugin installed on the webapp classpath.
- An existing regular instance `caa.conf`. The migration preserves links, but
  this policy-replacement test deliberately refuses linked configuration files.
- The libunbound plugin additionally needs its installed JNI bridge and system
  library. A standalone Maven unit run does not install either plugin.
- Bash, Python, Certbot (including its `acme`/`josepy` modules), cryptography,
  OpenSSL, curl, timeout, flock, PKI CLI and systemctl.
- `dnsmasq` and `dig` for unchecked CAA tests. DNSSEC tests additionally use
  BIND/signing tools and an Unbound daemon. Fedora packages include `bind`,
  `bind-utils`, `bind-dnssec-utils`, `unbound`, `dnsmasq`, `certbot` and
  `python3-cryptography`.
- Root access for the standalone HTTP-01 listener and service restarts. The
  test name must resolve to this host from both the client and ACME responder;
  port 80 and loopback ports 1053/1054 must be free.

Run from the checkout:

```sh
bash tests/caa-plugin/enrollment/test-enrollment.sh --caa --provider dnsjava --upgrade-check
bash tests/caa-plugin/enrollment/test-enrollment.sh --caa --provider libunbound --upgrade-check
bash tests/caa-plugin/enrollment/test-enrollment.sh --dnssec --provider dnsjava
bash tests/caa-plugin/enrollment/test-enrollment.sh --dnssec --provider dnsjava-local
bash tests/caa-plugin/enrollment/test-enrollment.sh --dnssec --provider libunbound
```

Use `--instance`, `--directory-url`, `--domain` and `--ca-cert` for a different
test installation. Defaults are instance `pki-tomcat`, directory
`https://pki.example.com:8443/acme/directory` and name `pki.example.com`. Without
`--ca-cert`, the script exports the instance's `ca_signing` certificate. TLS
verification remains enabled. DNSSEC fixtures use a private signed hierarchy
and require a single label under `example.com`; no public root trust changes.

Unchecked mode checks allow, deny and DNS outage. DNSSEC mode checks secure
allow/deny, a tampered signature, authenticated insecurity, signed alias/absence
with parent discovery, and outage. Each scenario uses fresh client state.
With `--provider dnsjava`, DNSSEC is validated by the fixture Unbound daemon,
not dnsjava's built-in validator. With `--provider dnsjava-local`, dnsjava
validates in process using the fixture trust anchor. With `--provider libunbound`,
the native library validates in process with that same anchor. Both local
providers query the authoritative BIND fixture directly.
Successful issuance must have the exact requested DNS SAN set, no unexpected
CN, a matching private key, and a valid chain to the test CA. An authenticated
POST-as-GET verifies the persisted order status and certificate/error state.
Rejected orders must be invalid, contain the expected CAA/DNS error and have
no certificate URL or downloaded certificate.

`--upgrade-check` requires the proposed migration to be installed. It tests
missing-file creation, PKI ownership/permissions and rollback with isolated
backup records, then exercises preservation through the real `pki-server
upgrade` command. The original policy is restored before service restart.
This tests migration and restart, not an old-to-new RPM transaction. It does
not reset upgrade trackers. Upgrade-directory numbering must match the release
that delivers the feature.

An exclusive lock prevents concurrent runs. EXIT/INT/TERM cleanup restores
policy, restarts the service, removes temporary anchors and stops owned DNS
processes with bounded waits. SIGKILL cannot trigger cleanup. A private results
directory retains client keys, logs, the original policy and verified order
JSON; do not publish that directory. CI uploads only the summary log.

These tests cover one non-wildcard name and HTTP-01. Wildcard/multi-SAN
enrollment, renewal, CA route exclusivity, malicious profile changes, delayed
signing, target RHCS packaging/FIPS and native heap tools remain separate
qualification. The domain-control DNS path is independent of the CAA plugin.

Harness and order-verifier unit tests require only Python's standard library:

```sh
python3 -m unittest discover -s tests/caa-plugin/enrollment -p 'test_*.py' -v
```
