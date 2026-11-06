# CAA policy, issuance gate and DNS plugin tests

These standalone tests compile the actual ACME CAA sources and optional
production adapters with `--release 17`. No full PKI build is needed.
The default suite has no DNS library dependency or network requirement.

**Security-sensitive:** issuance authorization, DNS evidence and JNI require
extra review. Fixture success is not RHCS installation or public-trust qualification.

The [coverage map](COVERAGE.md) lists each suite, tested boundaries and remaining
qualification work. There are 130 standalone unit tests, 22 actual ACME-engine
tests, eight opt-in DNSSEC integration tests and four shared operational tests.

Start with [prerequisites and offline preparation](../../base/acme/caa-plugins/PREREQUISITES.md) for the
software, native packages and Maven/PNC inputs to supply on a review machine.
These instructions work from a checkout without a particular development image.

## Layout

- `acme`: contract, provider loading, discovery/policy and issuance-gate tests.
  `TestCAALookupBudget` is a test-only fixture, shared in a test JAR.
- `dnsjava`: compiles `base/acme/caa-plugins/dnsjava`; tests binary TCP responses,
  aliases, negative answers, AD interpretation and lifecycle.
- `libunbound`: compiles `base/acme/caa-plugins/libunbound`; tests real JNI calls,
  signed/insecure/bogus/negative fixtures, evidence cross-checks and cancellation.
  dnsjava is a test dependency only, used to construct/sign fixture packets.
- `dnssec`: opt-in integration tests against real BIND and Unbound processes,
  using a private signed root/com/example.com hierarchy. All three validation paths run
  through the actual CAA issuance gate, with a recording issuer callback.
- `operational`: shared timeout, saturation, cancellation, interruption and
  recovery workload against both real plugins.
- `enrollment`: portable Certbot-to-CA tests, authenticated persisted-order
  verification and isolated tests of harness restoration/error handling.

No deliverable adapter lives under tests. Both optional profiles can be selected
independently or together. Neither adapter is needed for default builds.

## Run

Use the [pinned PNC dnsjava helper](pnc/README.md) for local prototype builds.
It verifies the JAR/POM and uses a separate cache so an existing Central copy
cannot be selected accidentally. The default core suite needs neither PNC nor
a DNS library. Raw Maven commands still use normal repository resolution;
they do not select the PNC binary by themselves.

From the repository root, with Maven dependencies available:

```sh
mvn -B -f tests/caa-plugin/pom.xml test
python3 tests/caa-plugin/pnc/pnc_dnsjava.py -- \
  -f tests/caa-plugin/pom.xml -Pdnsjava test

# Requires libunbound development packages and loopback TCP access.
sh tests/caa-plugin/libunbound/build-native.sh
python3 tests/caa-plugin/pnc/pnc_dnsjava.py -- \
  -f tests/caa-plugin/pom.xml -Plibunbound test
python3 tests/caa-plugin/pnc/pnc_dnsjava.py -- \
  -f tests/caa-plugin/pom.xml -Pdnsjava,libunbound test
```

Add `-o` for cached offline builds. `clean` removes the native output, so rebuild
JNI after cleaning. The native profile runs with `-Xcheck:jni` and its generated
native directory on `java.library.path`; do not install a system bridge to run it.

Actual ACME-engine integration tests live in
`base/acme/src/test/java/org/dogtagpki/acme/server/ACMEEngineCAATest.java`.
They verify call ordering, issuer suppression and persisted ACME order failures.

The test driver calls CSR validation, CAA validation and the issuer explicitly,
matching the servlet's call sequence. It does not execute the HTTP/JWS handler.

Run with the normal PKI Java build dependencies:

```sh
mvn -B -pl base/acme -am -Dapi.v1=true \
  -Dtest=ACMEEngineCAATest -Dsurefire.failIfNoSpecifiedTests=false test
```

The configuration migration has eight standard-library Python tests, also run
by the CAA unit workflow. They test the shipped script with isolated files and
a stubbed upgrade framework; they do not perform an RPM transaction:

```sh
python3 -m unittest discover -s tests/caa-plugin/upgrade -v
```

The surrounding upstream reactor uses Java 21. The standalone CAA/plugin sources
compile as Java 17. RHCS 10.8/RHEL 8.10 runtime, RPM transactions, native heap
tooling and FIPS qualification remain.

See the [plugin guide](../../base/acme/caa-plugins/README.md) for administrator
configuration, issuance behavior and optional build selection.

## GitHub Actions coverage

The CAA-specific jobs in [ACME CAA Tests](../../.github/workflows/acme-caa-test.yml)
and the ACME umbrella workflow are disabled, including adapter artifact
preparation and enrollment. PNC inputs require internal connectivity or approved
artifact transfer before these jobs can be re-enabled. Unrelated ACME jobs
remain enabled. The retained job definitions describe the intended coverage:

- Java 17 and 21 jobs run the 130 standalone policy, gate and plugin tests.
  They also run the four shared operational tests. The native bridge is built
  from this checkout and runs with `-Xcheck:jni`.
- A Java 17 job runs six DNSSEC scenarios through three validation paths: secure allow,
  secure deny, bogus signature, authenticated insecurity, signed alias/negative
  answers followed by parent discovery, and resolver outage. Two additional
  cases check local dnsjava root-anchor failure and DNSKEY snapshots.
- The [ACME image build](../../.github/workflows/acme-tests.yml) separately runs
  the 22 actual ACME-engine tests in its Fedora builder, with the full PKI/JSS
  dependencies. Those tests use a recording issuer and deterministic DNS provider.

Required-suite report checks reject missing, empty, skipped or failing suites.
Surefire reports and DNS server logs are uploaded on failure as well as success.
The DNSSEC suite has eight test methods. Six exercise all three validation
paths; two cover local dnsjava anchor handling. They add to the existing
152 Java unit tests; four operational tests bring the total to 164. The 19 Python
migration/harness/order-verifier checks are separate.

DNSSEC does not require public DNS access in CI. BIND serves generated zones on
`127.0.0.1:1054`; Unbound validates against a generated private root DS anchor
on `127.0.0.1:1053`. Delegated dnsjava queries Unbound; in-process dnsjava and
libunbound query BIND directly and validate locally. Each scenario starts fresh
processes and proves that the private root validates before checking outcomes. The bogus scenario changes
CAA RDATA after signing and requires a validation failure, not a generic timeout.
Daemons are stopped with bounded waits. System DNS and system trust anchors
remain unchanged. Reserve those two ports; do not run multiple instances of
this fixture concurrently.

To run the same DNSSEC integration tests locally, install BIND signing tools,
Unbound, libunbound headers, a C compiler and pkg-config. On Fedora the signing
tools are in `bind-dnssec-utils`; on Ubuntu they are in `bind9-utils`.

```sh
sh tests/caa-plugin/libunbound/build-native.sh
python3 tests/caa-plugin/pnc/pnc_dnsjava.py -- \
  -f tests/caa-plugin/pom.xml \
  -Pdnsjava,libunbound,dnssec-integration \
  -Dtest=CAADNSSECIntegrationTest -Dsurefire.failIfNoSpecifiedTests=false test
python3 tests/caa-plugin/check-reports.py dnssec
```

Ubuntu's packaged AppArmor profiles can restrict DNS daemons to system directories.
The workflow adds access only to the generated fixture directory, without disabling
the profiles. A locally confined daemon needs equivalent permission. The test
processes themselves use high loopback ports and do not require root.

The disabled CAA enrollment job is configured to invoke the existing basic ACME
workflow with its `caa` input enabled. After ordinary enrollment checks, it installs the
optional adapters as test artifacts and runs the portable enrollment suite
below. This keeps them out of default RPM builds and does not qualify supported
dependency delivery. Public root-anchor
rollovers, NSEC3/opt-out, target RHEL/RHCS packaging/runtime and FIPS qualification
remain separate work. GitHub's Ubuntu Java matrix is additional portability
coverage, not RHCS qualification.

## Operational workload

```sh
sh tests/caa-plugin/libunbound/build-native.sh
python3 tests/caa-plugin/pnc/pnc_dnsjava.py -- \
  -f tests/caa-plugin/pom.xml -Pdnsjava,libunbound,operational test
python3 tests/caa-plugin/check-reports.py operational
```

Each test runs against both unchecked providers using the same TCP impairment
server. It covers 24 consecutive timeouts followed by recovery, eight admitted
checks plus sixteen excess checks, cancellation of eight active calls, and
caller interruption followed by reuse. Linux descriptor/OS-thread counts and
JVM thread counts are sampled after warmup and checked for bounded growth. Timing/resource
allowances include scheduling and shared transport-pool tolerance. These are
bounded regression checks, not a sustained-load benchmark, native heap leak
proof or a worst-case guarantee for every native library operation. DNSSEC
cryptographic behavior is covered separately by the signed fixtures.

## Real ACME enrollment

See [enrollment prerequisites and commands](enrollment/README.md). The portable
script runs against an already configured disposable CA/ACME host, checks the
actual servlet path and final certificate names, fetches the persisted order
with the client's account, and restores the original CAA policy afterward.
