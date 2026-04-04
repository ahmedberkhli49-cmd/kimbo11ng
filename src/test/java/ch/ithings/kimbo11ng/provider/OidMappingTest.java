/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies the OID → JCA algorithm mapping in Kimbo11ngPublicKey.
 *
 * The NIST PQC OID layout under 2.16.840.1.101.3.4.3:
 *   .17-.19  ML-DSA  (FIPS 204)
 *   .20-.25  SLH-DSA SHA2  (FIPS 205)
 *   .26-.31  SLH-DSA SHAKE (FIPS 205)
 *
 * And under 2.16.840.1.101.3.4.4:
 *   .1-.3    ML-KEM  (FIPS 203)
 *
 * A previous bug had the SLH-DSA OIDs interleaved (SHA2/SHAKE alternating)
 * instead of grouped.  This test locks in the correct grouping.
 */
class OidMappingTest {

    private static Method spkiAlgorithm;

    @BeforeAll
    static void reflectMethod() throws Exception {
        spkiAlgorithm = Kimbo11ngPublicKey.class
                .getDeclaredMethod("spkiAlgorithm", ASN1ObjectIdentifier.class);
        spkiAlgorithm.setAccessible(true);
    }

    private String map(String oid) throws Exception {
        return (String) spkiAlgorithm.invoke(null, new ASN1ObjectIdentifier(oid));
    }

    // ─── ML-DSA (.17-.19) ────────────────────────────────────────────────────

    @ParameterizedTest
    @CsvSource({
        "2.16.840.1.101.3.4.3.17, ML-DSA",
        "2.16.840.1.101.3.4.3.18, ML-DSA",
        "2.16.840.1.101.3.4.3.19, ML-DSA",
    })
    void mlDsaOids(String oid, String expected) throws Exception {
        assertEquals(expected, map(oid));
    }

    // ─── SLH-DSA SHA2 group (.20-.25) ────────────────────────────────────────

    @ParameterizedTest
    @CsvSource({
        "2.16.840.1.101.3.4.3.20, SLH-DSA",   // SHA2-128S
        "2.16.840.1.101.3.4.3.21, SLH-DSA",   // SHA2-128F
        "2.16.840.1.101.3.4.3.22, SLH-DSA",   // SHA2-192S
        "2.16.840.1.101.3.4.3.23, SLH-DSA",   // SHA2-192F
        "2.16.840.1.101.3.4.3.24, SLH-DSA",   // SHA2-256S
        "2.16.840.1.101.3.4.3.25, SLH-DSA",   // SHA2-256F
    })
    void slhDsaSha2Oids(String oid, String expected) throws Exception {
        assertEquals(expected, map(oid));
    }

    // ─── SLH-DSA SHAKE group (.26-.31) ───────────────────────────────────────

    @ParameterizedTest
    @CsvSource({
        "2.16.840.1.101.3.4.3.26, SLH-DSA",   // SHAKE-128S
        "2.16.840.1.101.3.4.3.27, SLH-DSA",   // SHAKE-128F
        "2.16.840.1.101.3.4.3.28, SLH-DSA",   // SHAKE-192S
        "2.16.840.1.101.3.4.3.29, SLH-DSA",   // SHAKE-192F
        "2.16.840.1.101.3.4.3.30, SLH-DSA",   // SHAKE-256S
        "2.16.840.1.101.3.4.3.31, SLH-DSA",   // SHAKE-256F
    })
    void slhDsaShakeOids(String oid, String expected) throws Exception {
        assertEquals(expected, map(oid));
    }

    // ─── ML-KEM (.1-.3 under .4.4) ───────────────────────────────────────────

    @ParameterizedTest
    @CsvSource({
        "2.16.840.1.101.3.4.4.1, ML-KEM",
        "2.16.840.1.101.3.4.4.2, ML-KEM",
        "2.16.840.1.101.3.4.4.3, ML-KEM",
    })
    void mlKemOids(String oid, String expected) throws Exception {
        assertEquals(expected, map(oid));
    }

    // ─── Boundary checks: adjacent OIDs must NOT map ─────────────────────────

    @Test
    void oidBelowMlDsaRange_returnsNull() throws Exception {
        assertNull(map("2.16.840.1.101.3.4.3.16")); // one below ML-DSA-44
    }

    @Test
    void oidAboveSlhDsaRange_returnsNull() throws Exception {
        assertNull(map("2.16.840.1.101.3.4.3.32")); // one above SHAKE-256F
    }

    @Test
    void unrelatedOid_returnsNull() throws Exception {
        assertNull(map("1.2.840.10045.4.3.2")); // SHA256withECDSA
    }
}
