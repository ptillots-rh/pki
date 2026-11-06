# Optional ACME CAA DNS plugins

Each flavor implements the CAA DNS interface in ACME core and builds as a
separate optional artifact:

```text
base/acme/
  src/main/java/org/dogtagpki/acme/caa/   CAA policy, gate and DNS interface
  caa-plugins/
    dnsjava/                            Java DNS client
    libunbound/                         Embedded native resolver and JNI bridge
```

The [dnsjava](dnsjava/README.md) and [libunbound](libunbound/README.md) guides
cover their build options and dependencies. Both default off and can be built
independently or together. Artifact names, provider class names and existing
build flags are unchanged by this source layout.

See [prerequisites and offline preparation](PREREQUISITES.md) for the tools,
native packages and Maven inputs reviewers need before building or testing.

Local dnsjava builds use the [pinned PNC artifact](../../../tests/caa-plugin/pnc/README.md).
CAA-specific GitHub jobs are disabled until that input can be supplied to the
runners.

Production Maven profiles remain in `base/pom.xml`, with explicit nested module
paths. Each plugin inherits that parent using `../../../pom.xml`. ACME itself
remains a JAR module; the grouping directory adds no Maven parent or artifact.
CMake selects the flavors through this directory after defining ACME core.

## ACME configuration

The installed default is `/usr/share/pki/acme/conf/caa.conf`. New ACME
deployments copy it to `/etc/pki/<instance>/acme/caa.conf`, also accessible
through `/var/lib/pki/<instance>/conf/acme/caa.conf`. Missing configuration
on an older instance means CAA is disabled. Both adapters are omitted from
default builds, and CAA remains disabled until explicitly configured.

The server upgrade script `11.10.1/01-AddACMECAAConfig.py` creates a missing
instance policy from the shipped default-off template. It preserves existing
configuration and skips non-ACME subsystems. The normal instance copy helper
applies ownership and file permissions, and the upgrade framework records the
new file for rollback. PKI's service pre-start upgrade runs this migration;
custom service launchers must run `pki-server upgrade <instance>` themselves.
The missing-file compatibility fallback remains for older, unmigrated instances.

After installing an adapter, edit the instance's `caa.conf`:

```properties
enabled=true
issuerIdentifiers=ca.example.com
dns.class=org.dogtagpki.acme.caa.dnsjava.DNSJavaCAAProvider
dns.settings.server=127.0.0.1
dns.settings.port=53
```

Use the issuer identifier published in the CA's CPS. Multiple identifiers are
comma-separated. `dns.class` names an installed provider, and `dns.settings.*`
are passed to that provider without the prefix. The example selects unchecked
DNS resolution. The individual adapter guides explain their DNSSEC providers
and prerequisites; there is no separate configurable validation mode.

Restart the entire PKI/Tomcat instance after changing the policy, provider,
native library or trust anchors. There is no hot reload. Invalid enabled
configuration prevents CAA initialization rather than disabling enforcement.

## Issuance behavior

The steps remain explicit in the servlet. The CAA check returns normally only
when checking is disabled or the request is authorized:

```text
ACMEOrderServlet.finalizeOrder()
  |
  +-> engine.validateCSR(account, order, csr)
  |     Reject invalid CSR before CAA or issuer submission
  |
  +-> engine.validateCAA(account, order, csr)
  |     |
  |     +-> ACMECAAValidator
  |           |
  |           +-> CAA disabled: return without loading a DNS plugin
  |           |
  |           +-> Build names and trusted account/method context
  |           |
  |           +-> CAAIssuanceGate.check()
  |                 |
  |                 +-> DefaultCAAValidator
  |                 |     Discover relevant CAA and evaluate issuer policy
  |                 |       |
  |                 |       +-> CAADNSClient.resolveCaa(candidate, budget)
  |                 |             Selected plugin returns DNS/alias evidence
  |                 |
  |                 +-> ALLOW and unexpired: return
  |                 +-> DENY or ERROR: invalidate order, throw ACME error
  |                                      (issuer is not called)
  |
  +-> issuer.issueCertificate(csr)
  |
  +-> Store certificate ID and mark order valid after successful issuance
```

The policy engine can make multiple lookups for names, aliases and parent
candidates. The plugin follows aliases; parent discovery stays in the policy
engine. A context-building failure also rejects the order before submission.
The diagram shows the normal path; issuer failures propagate to the existing
servlet error handling.

During order finalization, the servlet explicitly calls `validateCSR()`, then
`validateCAA()`, then `issuer.issueCertificate()`. A failed check throws before
the issuer is invoked. The CAA adapter uses the CSR's extracted DNS names and
stored, account-owned authorizations to construct trusted per-name context.
The package-private `ACMECAAValidator` adapter owns configuration loading,
context mapping, audit messages and ACME error persistence. `ACMEEngine`
only initializes/closes it and delegates the CAA check. Issuance remains in
the servlet.
The shared policy engine performs parent discovery, wildcard and critical-tag
processing, issuer matching and applicable account/method binding checks.
The DNS adapter resolves aliases and returns DNS evidence; it does not decide
CAA authorization or replace domain-control challenges.

The dnsjava adapter supports both delegation to an enforcing resolver, tested
with Unbound, and in-process validation using dnsjava's built-in validator.
The implemented DNSSEC validation paths are:

```text
Delegated DNSSEC (dnsjava)

  CAA engine -> dnsjava -> trusted enforcing loopback resolver -> DNS
                          ^
                          DNSSEC validation and anchor management occur here

Local DNSSEC (dnsjava)

  CAA engine -> dnsjava ValidatingResolver -> configured DNS endpoint -> DNS
                ^
                DNSSEC validation occurs inside ACME using static anchors
                provisioned and updated by an external owner

Local DNSSEC (libunbound)

  CAA engine -> Java/JNI -> libunbound -> configured forwarder -> DNS
                           ^
                           DNSSEC validation occurs here using static anchors
                           provisioned and updated by an external owner
```

Only the configured plugin is used; these are alternatives, not a fallback
chain. Both also have unchecked providers for operation without DNSSEC
assurance. The DNSSEC provider variants block unusable validation outcomes;
delegated mode relies on the trusted resolver enforcing that policy. Neither
adapter starts or manages a resolver daemon. See each adapter guide for its
configuration and trust-anchor requirements.

A denial or unusable DNS/DNSSEC result blocks issuer submission and invalidates
the order. Service logging records the order, name, wildcard status, outcome
and reason without raw DNS values or account URIs. These are service events,
not a new signed-audit event or persistent DNS-evidence store.

For public-TLS issuance restricted to ACME, CA authorization and profile controls
must prevent equivalent unchecked enrollment routes. Profiles must preserve
the checked final names, and queues or retries must preserve decision freshness
through signing. This implementation guards submission; it does not enforce
freshness inside a remote CA's signing queue or add CA-side DNS lookups.
Systems sharing an issuer identifier must coordinate their RFC 8657 binding
policy. These deployment guarantees require separate verification.

## Tests

The [CAA test guide](../../../tests/caa-plugin/README.md) provides standalone
unit, ACME-engine and private-hierarchy DNSSEC commands. The corresponding
CAA GitHub jobs are temporarily disabled for the PNC input transition.
Neither adapter is required by the default PKI RPM build.

## Reviewer considerations

Security-sensitive: these plugins process untrusted DNS data for issuance
approval. Review trust interpretation, native ownership and standards behavior
in addition to the ordinary Java integration. The items below distinguish
deployment decisions from remaining qualification; passing fixtures do not
establish supported RHCS delivery or complete public-trust compliance.

### Scope and delivery decisions

- **ACME-only enforcement:** confirm that CA authorization, permitted profiles
  and network restrictions make ACME the exclusive route for the covered
  certificates. Include direct enrollment, manual approval and renewal when
  checking bypasses. mTLS identifies ACME; it does not prove that a CAA check
  happened. Independently signing issuers need separate qualification. Evaluate
  existing controls before introducing new CA code or evidence tokens.
- **Names and freshness through signing:** the explicit servlet check covers
  extracted CSR names, not later profile modifications. Verify the final names,
  wildcard status and issuer policy on the actual CA path. `validateCAA()`
  returns approval for that immediate attempt, not a reusable authorization
  token. Queues, delayed approval, changed names and retries require an agreed
  freshness/revalidation arrangement; no CA-side queue guard is implemented.
- **Dependency delivery:** approve the RHCS build/runtime source and name the
  maintenance/security-update owner. The current dnsjava RPM path requires a
  Maven-capability provider; it does not implement PNC import or RHCS JAR
  bundling. Test artifacts fetched for CI do not qualify delivery. For IdM,
  verify that omitting both adapters and their dependencies is sufficient:
  the inactive CAA core and servlet hook remain in the default ACME build.
- **Upgrade and configuration policy:** align the migration directory with the
  actual delivery release. The current script is under `11.10.1`; backports or
  another target release need corresponding numbering and test references.
  Existing files/links are preserved. The missing-file fallback still disables
  CAA, including after deletion or a broken configuration link and restart.
  Decide how covered deployments detect disabled checking and configuration
  drift, including differences between replicas. Defaults must preserve
  existing private-CA workflows.
- **Operational failure behavior:** DNS failures and overload currently
  invalidate the order, so the client needs a new order rather than retrying
  finalization on the same one. Review that behavior and the fixed five-second
  total budget, one-second lookup cap and eight concurrent checks per validator.
  These are not deployment-wide or HTTP admission limits. Service logs contain
  outcomes/reasons, not retained DNS evidence or new signed-audit events; agree
  on the required operational visibility and retention.

### DNSSEC responsibilities

- **dnsjava delegation:** the configured loopback resolver must enforce
  validation. An AD-clear success is not proof of an unsigned domain; accepting
  it relies on the resolver withholding bogus answers. Review effective
  configuration, policy changes, outages and recovery. A startup probe alone
  cannot establish continuous enforcement. This provider does not implement
  authenticated remote DNS, resolver deployment or anchor management.
- **Embedded dnsjava:** select `DNSJavaCAAProvider$Validating` and configure
  `dns.settings.trustAnchors`. The adapter validates locally and does not trust
  upstream AD. An external owner maintains the static DS/DNSKEY anchor file;
  restart ACME after changes. No RFC 5011 updater or persistent cross-candidate
  key cache is included. Root anchors permit established insecurity; zone-only
  anchors require secure results. Supporting queries share the lookup budget.
  Review crypto/provider behavior, validation CPU costs and resource limits.
- **Embedded libunbound:** an external owner must bootstrap, update and recover
  the static trusted-anchor export and restart ACME when it changes. There is
  no RFC 5011 updater or automatic anchor reload. Review JNI cancellation,
  context/result ownership and the detached packet reader. Each lookup creates
  its own native context and may validate the root; assess that cost before
  choosing a cache or pooling design. Multiple ACME class loaders and hot
  redeployment are not qualified.
- **Binding and standards policy:** coordinate RFC 8657 support across systems
  sharing an issuer identifier. ACME uses stored account-owned authorizations;
  missing or ambiguous method context cannot satisfy a method-bound grant.
  Review the chosen treatment of unsupported parameters and document supported
  semantics. DNSSEC implementation phasing is not a claim that an unchecked
  provider satisfies requirements applicable to public-TLS issuance.

### Evidence and remaining qualification

The test suite includes real servlet-to-CA enrollment for both plugins, exact
single-name certificate checks, authenticated persisted-order checks, private
secure/insecure/bogus DNSSEC fixtures, migration/restart checks and bounded
timeout/concurrency/recovery workloads. The [coverage map](../../../tests/caa-plugin/COVERAGE.md)
and [enrollment guide](../../../tests/caa-plugin/enrollment/README.md) describe
the boundaries and commands.

- **Broader issuance cases:** add wildcard and multi-SAN enrollment, renewal,
  live account/method-bound CAA cases, profile-induced name changes, signing
  delays and unauthorized alternate routes. Current live tests use HTTP-01 and
  one name with the test profile; they do not establish all of these guarantees.
- **DNSSEC and resource extremes:** extend coverage to NSEC3/opt-out, cross-zone
  signed alias chains, key rollover and resolver misconfiguration. Descriptor
  and JVM/OS-thread checks are bounded regressions, not native heap-safety proof
  or sustained-load qualification. Fuzzing, native memory/race tools and worst-
  case native initialization/teardown timing remain outstanding.
- **Exact product deployment:** qualify the intended RHCS/RHEL/JDK combination,
  library APIs/algorithms, crypto-provider/FIPS behavior, SELinux permissions,
  installation/removal and actual old-to-new RPM transactions. The prototype's
  migration-command tests and GitHub Java matrix do not replace those checks.
