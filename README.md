# kimbo11ng

Open-source PKCS#11 NG CryptoToken for [EJBCA CE](https://www.ejbca.org/) with post-quantum cryptography support.

Backed by [JackNJI11](https://github.com/joelhockey/jacknji11) (Apache 2.0 JNA PKCS#11 bindings) and tested against [softhsmv3](https://github.com/pqctoday/softhsmv3) with OpenSSL 3.6+.

## Features

- Drop-in `Pkcs11NgCryptoToken` for EJBCA CE 9.3.7
- RSA and EC key generation, signing, and verification via PKCS#11
- **Post-quantum cryptography**: ML-DSA (FIPS 204), ML-KEM (FIPS 203), and SLH-DSA (FIPS 205)
- Vendor-agnostic `PqcMechanismProfile` abstraction for HSM-specific PQC constants
- No SunPKCS11 dependency — pure JNA bindings, supports multiple HSM libraries simultaneously

## Supported Algorithms

| Algorithm | Key Specs                                    | Standard        |
| --------- | -------------------------------------------- | --------------- |
| RSA       | 2048, 3072, 4096                             | PKCS#1          |
| EC        | P-256, P-384, P-521, brainpool               | NIST / RFC 5639 |
| ML-DSA    | ML-DSA-44, ML-DSA-65, ML-DSA-87              | FIPS 204        |
| ML-KEM    | ML-KEM-512, ML-KEM-768, ML-KEM-1024          | FIPS 203        |
| SLH-DSA   | SHA2/SHAKE x 128/192/256 x S/F (12 variants) | FIPS 205        |
| Hybrid    | RSA/EC primary + ML-DSA/SLH-DSA alternative  | X.509 Sec. 9.8  |

## Prerequisites

- Docker
- [just](https://github.com/casey/just) command runner
- Maven 3.8+ and JDK 17+

## Quick Start

```bash
# Full pipeline: setup + build Docker image + start + provision token + integration tests
just ci

# Or step by step:
just setup          # extract JARs from EJBCA image + install + build
just docker-build   # build Docker image (EJBCA + softhsmv3 + kimbo11ng)
just up             # start EJBCA + PostgreSQL
just create-token   # provision TestHSM as Pkcs11NgCryptoToken

# Run integration tests (Testcontainers — starts a fresh stack automatically)
mvn verify -Pit
```

## Version Matrix

All versions are centralized in the `justfile`. Run `just versions` to display:

```
EJBCA:     9.3.7 (keyfactor/ejbca-ce:9.3.7)
OpenSSL:   3.6.0
Artifact:  kimbo11ng-1.0.0-SNAPSHOT-jar-with-dependencies.jar

Dependencies:
  com.keyfactor:cryptotokens-api:3.0.0
  com.keyfactor:cryptotokens-impl:3.0.0
  org.pkcs11:jacknji11:1.3.1
  org.cesecore:cesecore-common:9.3.7
  com.keyfactor:x509-common-util:5.3.5
```

To upgrade EJBCA, update `ejbca_version` and `ejbca_deps` in the justfile, then:

```bash
just extract-jars-fresh setup docker-build
mvn verify -Pit
```

## Build Recipes

| Recipe                    | Description                                                                 |
| ------------------------- | --------------------------------------------------------------------------- |
| `just setup`              | Extract EJBCA JARs + install to Maven + build                               |
| `just build`              | Build the fat JAR                                                           |
| `just deploy`             | Hot-reload JAR into running EJBCA container                                 |
| `just docker-build`       | Build Docker image (EJBCA + softhsmv3 + kimbo11ng)                          |
| `just up` / `just down`   | Start / stop services                                                       |
| `just create-token`       | Provision TestHSM as Pkcs11NgCryptoToken (idempotent)                       |
| `just ci`                 | Full pipeline: setup + docker-build + up + create-token + integration tests |
| `just extract-jars-fresh` | Force re-extract JARs (after EJBCA version bump)                            |
| `just versions`           | Show version matrix                                                         |
| `just status`             | Show versions, git log, Docker, and artifact status                         |
| `just clean-all`          | Remove build artifacts and extracted deps                                   |

## Integration Tests

The integration test suite (`EjbcaContainerIT`) runs against a full EJBCA CE stack managed by Testcontainers (Docker Compose). It covers:

- PKCS#11 key generation: RSA, EC, ML-DSA, ML-KEM, SLH-DSA
- Key listing and test-signing via the PKCS#11 token
- PQC Root CA creation: ML-DSA-65, SLH-DSA-SHA2-128F, Hybrid (RSA + ML-DSA alternative)
- Certificate issuance from each CA and signature algorithm verification

```bash
mvn verify -Pit          # runs all 18 integration tests (~4 min)
```

Requires Docker. The test image is built automatically by `just docker-build`.

## Project Structure

```
kimbo11ng/
  src/
    main/java/
      ch/ithings/kimbo11ng/          # Core implementation
        provider/                    # JCA provider, KeyStore, Signature SPIs
        profile/                     # PQC mechanism profiles (v3.2, Thales, ...)
        slot/                        # PKCS#11 slot enumeration
      org/cesecore/.../              # EJBCA entry point (thin delegate)
      com/keyfactor/.../             # EJBCA SPI factory (thin delegate)
    test/java/
      ch/ithings/kimbo11ng/          # Unit tests (profile, OID mapping, public key)
    it/java/
      ch/ithings/kimbo11ng/it/       # Integration tests (EjbcaContainerIT — 18 tests)
    it/openapi/
      ejbca-api.json                 # EJBCA CE REST API spec (OpenAPI)
  docker/                            # Dockerfile, softhsmv3 config
  deps/ejbca/                        # Extracted EJBCA JARs (gitignored)
  pom.xml                            # Maven build (ch.ithings:kimbo11ng)
  justfile                           # Build automation recipes
  docker-compose.yml                 # EJBCA + PostgreSQL stack
```

## License

[Apache License 2.0](LICENSE) — Copyright (c) 2026 Thomas Pham.
