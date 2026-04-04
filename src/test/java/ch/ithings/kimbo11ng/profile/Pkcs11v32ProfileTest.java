/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.pkcs11.jacknji11.CKK;

import java.security.InvalidAlgorithmParameterException;

import static org.junit.jupiter.api.Assertions.*;

class Pkcs11v32ProfileTest {

    private Pkcs11v32Profile profile;

    @BeforeEach
    void setUp() {
        profile = new Pkcs11v32Profile();
    }

    // ─── ML-DSA ──────────────────────────────────────────────────────────────

    @ParameterizedTest
    @CsvSource({
        "ML-DSA-44, 1",
        "ML-DSA-65, 2",
        "ML-DSA-87, 3",
        "ml-dsa-44, 1",
        "MLDSA44,   1",
        "mldsa_65,  2",
    })
    void resolveMlDsaParamSet(String keySpec, long expected) throws Exception {
        assertEquals(expected, profile.resolveMlDsaParamSet(keySpec));
    }

    @Test
    void resolveMlDsaParamSet_unknown_throws() {
        assertThrows(InvalidAlgorithmParameterException.class,
                () -> profile.resolveMlDsaParamSet("ML-DSA-128"));
    }

    // ─── ML-KEM ──────────────────────────────────────────────────────────────

    @ParameterizedTest
    @CsvSource({
        "ML-KEM-512,  1",
        "ML-KEM-768,  2",
        "ML-KEM-1024, 3",
        "mlkem512,    1",
        "ML_KEM_768,  2",
    })
    void resolveMlKemParamSet(String keySpec, long expected) throws Exception {
        assertEquals(expected, profile.resolveMlKemParamSet(keySpec));
    }

    @Test
    void resolveMlKemParamSet_unknown_throws() {
        assertThrows(InvalidAlgorithmParameterException.class,
                () -> profile.resolveMlKemParamSet("ML-KEM-256"));
    }

    // ─── SLH-DSA: all 12 variants ────────────────────────────────────────────

    @ParameterizedTest
    @CsvSource({
        "SLH-DSA-SHA2-128S,  1",
        "SLH-DSA-SHAKE-128S, 2",
        "SLH-DSA-SHA2-128F,  3",
        "SLH-DSA-SHAKE-128F, 4",
        "SLH-DSA-SHA2-192S,  5",
        "SLH-DSA-SHAKE-192S, 6",
        "SLH-DSA-SHA2-192F,  7",
        "SLH-DSA-SHAKE-192F, 8",
        "SLH-DSA-SHA2-256S,  9",
        "SLH-DSA-SHAKE-256S, 10",
        "SLH-DSA-SHA2-256F,  11",
        "SLH-DSA-SHAKE-256F, 12",
    })
    void resolveSlhDsaParamSet_allVariants(String keySpec, long expected) throws Exception {
        assertEquals(expected, profile.resolveSlhDsaParamSet(keySpec));
    }

    @ParameterizedTest
    @CsvSource({
        "slh-dsa-sha2-128s,  1",
        "slhdsa_shake_128s,  2",
        "SLHDSA_SHA2_256F,   11",
        "slhdsashake256f,    12",
    })
    void resolveSlhDsaParamSet_normalizedForms(String keySpec, long expected) throws Exception {
        assertEquals(expected, profile.resolveSlhDsaParamSet(keySpec));
    }

    @Test
    void resolveSlhDsaParamSet_unknown_throws() {
        assertThrows(InvalidAlgorithmParameterException.class,
                () -> profile.resolveSlhDsaParamSet("SLH-DSA-SHA3-128S"));
    }

    // ─── algorithmForKeyType ──────────────────────────────────────────────────

    @Test
    void algorithmForKeyType_knownTypes() {
        assertEquals("RSA",     profile.algorithmForKeyType(CKK.RSA));
        assertEquals("EC",      profile.algorithmForKeyType(CKK.EC));
        assertEquals("ML-DSA",  profile.algorithmForKeyType(0x4AL));
        assertEquals("ML-KEM",  profile.algorithmForKeyType(0x49L));
        assertEquals("SLH-DSA", profile.algorithmForKeyType(0x4BL));
    }

    @Test
    void algorithmForKeyType_unknown_returnsNull() {
        assertNull(profile.algorithmForKeyType(0xFFFL));
    }

    // ─── keySpecForParams round-trip ──────────────────────────────────────────

    @ParameterizedTest
    @CsvSource({
        "1,  SLH-DSA-SHA2-128S",
        "2,  SLH-DSA-SHAKE-128S",
        "3,  SLH-DSA-SHA2-128F",
        "4,  SLH-DSA-SHAKE-128F",
        "5,  SLH-DSA-SHA2-192S",
        "6,  SLH-DSA-SHAKE-192S",
        "7,  SLH-DSA-SHA2-192F",
        "8,  SLH-DSA-SHAKE-192F",
        "9,  SLH-DSA-SHA2-256S",
        "10, SLH-DSA-SHAKE-256S",
        "11, SLH-DSA-SHA2-256F",
        "12, SLH-DSA-SHAKE-256F",
    })
    void keySpecForParams_slhDsa(long paramSet, String expected) {
        assertEquals(expected, profile.keySpecForParams(0x4BL, paramSet));
    }

    @ParameterizedTest
    @CsvSource({
        "1, ML-DSA-44",
        "2, ML-DSA-65",
        "3, ML-DSA-87",
    })
    void keySpecForParams_mlDsa(long paramSet, String expected) {
        assertEquals(expected, profile.keySpecForParams(0x4AL, paramSet));
    }

    @ParameterizedTest
    @CsvSource({
        "1, ML-KEM-512",
        "2, ML-KEM-768",
        "3, ML-KEM-1024",
    })
    void keySpecForParams_mlKem(long paramSet, String expected) {
        assertEquals(expected, profile.keySpecForParams(0x49L, paramSet));
    }

    // ─── supports ─────────────────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {"ML-DSA-65", "MLDSA44", "ML-KEM-768", "MLKEM512",
                            "SLH-DSA-SHA2-128F", "slhdsa-shake-256f"})
    void supports_pqcKeySpecs(String keySpec) {
        assertTrue(profile.supports(keySpec));
    }

    @ParameterizedTest
    @ValueSource(strings = {"RSA2048", "prime256v1", "P-384", "", "FALCON-512"})
    void supports_nonPqcKeySpecs(String keySpec) {
        assertFalse(profile.supports(keySpec));
    }

    @Test
    void supports_null_returnsFalse() {
        assertFalse(profile.supports(null));
    }
}
