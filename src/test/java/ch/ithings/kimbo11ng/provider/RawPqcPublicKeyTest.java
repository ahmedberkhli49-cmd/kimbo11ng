/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;

class RawPqcPublicKeyTest {

    @ParameterizedTest
    @CsvSource({
        "ML-DSA-44,          ML-DSA",
        "ML-DSA-65,          ML-DSA",
        "ML-DSA-87,          ML-DSA",
        "MLDSA65,            ML-DSA",
        "ml-dsa-65,          ML-DSA",
        "ML-KEM-512,         ML-KEM",
        "ML-KEM-768,         ML-KEM",
        "ML-KEM-1024,        ML-KEM",
        "MLKEM768,           ML-KEM",
        "SLH-DSA-SHA2-128F,  SLH-DSA",
        "SLH-DSA-SHAKE-256S, SLH-DSA",
        "slhdsa-sha2-128s,   SLH-DSA",
        "SLHDSA_SHAKE_256F,  SLH-DSA",
    })
    void getAlgorithm(String keySpec, String expectedAlgorithm) {
        Kimbo11ngPublicKey.RawPqcPublicKey key =
                new Kimbo11ngPublicKey.RawPqcPublicKey(keySpec, new byte[]{0x30, 0x01, 0x00});
        assertEquals(expectedAlgorithm, key.getAlgorithm());
    }

    @ParameterizedTest
    @CsvSource({
        "unknown-algo, unknown-algo",
        "FALCON-512,   FALCON-512",
    })
    void getAlgorithm_unknownKeySpec_returnsKeySpecAsIs(String keySpec, String expected) {
        Kimbo11ngPublicKey.RawPqcPublicKey key =
                new Kimbo11ngPublicKey.RawPqcPublicKey(keySpec, new byte[0]);
        assertEquals(expected, key.getAlgorithm());
    }

    @ParameterizedTest
    @CsvSource({"ML-DSA-65", "SLH-DSA-SHA2-128F", "ML-KEM-768"})
    void getFormat_alwaysX509(String keySpec) {
        Kimbo11ngPublicKey.RawPqcPublicKey key =
                new Kimbo11ngPublicKey.RawPqcPublicKey(keySpec, new byte[]{0x00});
        assertEquals("X.509", key.getFormat());
    }

    @ParameterizedTest
    @CsvSource({"ML-DSA-65", "SLH-DSA-SHA2-128F"})
    void getEncoded_returnsSameBytes(String keySpec) {
        byte[] bytes = {0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
        Kimbo11ngPublicKey.RawPqcPublicKey key =
                new Kimbo11ngPublicKey.RawPqcPublicKey(keySpec, bytes);
        assertArrayEquals(bytes, key.getEncoded());
    }
}
