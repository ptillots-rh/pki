# Building the prototype with PNC dnsjava

See [prerequisites and offline preparation](../../../base/acme/caa-plugins/PREREQUISITES.md) before running
on a new machine. The helper selects a library artifact; it does not install
the JDK, Maven, native packages or all dependencies needed by a new profile.

Local prototype builds use the dnsjava artifact produced by
[PNC build BSHSPFWQYXIAA](https://orch.pnc.engineering.redhat.com/pnc-web/builds/BSHSPFWQYXIAA/details).
Run the helper from the repository root, passing the normal Maven arguments
after `--`:

```sh
python3 tests/caa-plugin/pnc/pnc_dnsjava.py -- \
  -f tests/caa-plugin/pom.xml -Pdnsjava clean test
```

To build the production adapter and its required Java modules:

```sh
python3 tests/caa-plugin/pnc/pnc_dnsjava.py -- \
  -Pacme-dnsjava -pl base/acme/caa-plugins/dnsjava -am \
  -Dapi.v1=true package
```

The helper requires Python 3, Maven, trusted HTTPS access to the internal Indy
repository and network access for initially missing Maven tools/dependencies.
It downloads the JAR and its real POM, verifies their SHA-256 digests, and
installs them under their original `dnsjava:dnsjava:3.6.5` coordinates in a
separate Maven repository. It does not rebuild dnsjava.

The Python HTTPS client must trust the internal service's certificate chain.
Use the organization's approved CA installation, or point `SSL_CERT_FILE` at
an approved PEM bundle for the build command. Do not disable TLS verification.
These HTTPS CA certificates are separate from DNSSEC trust anchors. The helper
does not modify system or JVM trust stores.

The default cache is `~/.m2/pnc-dnsjava/BSHSPFWQYXIAA/`. Use `--cache-dir PATH`
before `--` to choose another location. Use a location outside Maven `target`
directories so that `clean` cannot delete the running build's repository.
The normal Maven cache is not replaced. A different cached artifact or PNC
download failure blocks the build; there is no fallback to Central for dnsjava.

Other dependencies and build plugins still use the normal Maven settings and
repositories. This helper changes the selected dnsjava binary, not the provenance
of every build input. Once all inputs are cached, add `--offline` before `--`
to prevent both PNC downloads and Maven network resolution.

## Recorded artifact

- Version: `3.6.5`.
- PNC build: `BSHSPFWQYXIAA`, successful, non-temporary, November 2, 2026.
- JAR SHA-256: `4720cb6acebc9179d16ddd2b1134a236c42799c3240cb353c9b5094b147a56ca`.
- POM SHA-256: `d50ea6f20e29a98f9571ff421c2f7154b24133e92848ce4bb5a6f11aa44e815c`.
- Build environment: RHEL 9, OpenJDK 25 and Maven 3.9.9. This is not runtime
  qualification for RHCS 10.8/RHEL 8.10/Java 17.
- The PNC build skipped tests. Run the CAA/plugin tests against its actual output.

**Security-sensitive:** the checksums pin the selected build outputs. They do not
establish RHCS release approval, verify the referenced provenance attestations,
or assign component security-update ownership. Changing the selected build
requires reviewing its source record and updating both checksums.

## GitHub and release builds

The CAA-specific GitHub jobs and adapter artifact preparation are disabled while
the approved artifact is reachable only from the internal network. Existing
unrelated ACME jobs remain enabled. Re-enabling CAA jobs requires internal
connectivity or an approved way to supply the selected artifact. The disabled
workflow commands and artifact paths are preserved for that later update;
they do not currently select the PNC binary. The Python helper and its tests
are local build tools and are not invoked by the disabled workflows.
No internal repository is added to the community
POMs: coordinates alone cannot distinguish this JAR from a cached Central copy.

The helper is prototype build tooling, not an RPM dependency or installation
mechanism. Bundling and the standard RHCS release-input arrangement are deferred.
For a manual CMake configuration, the verified input is available at
`<cache>/inputs/dnsjava-3.6.5.jar` and can be passed as `DNSJAVA_JAR`. The
existing CMake runtime link does not bundle that file; ensure a live test
instance uses the intended binary rather than a previously installed copy.

Run the helper's network-independent checks with:

```sh
python3 -m unittest discover -s tests/caa-plugin/pnc -v
```
