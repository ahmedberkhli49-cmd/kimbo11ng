/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import java.security.InvalidAlgorithmParameterException;

/**
 * Abstraction for PKCS#11 PQC mechanism constants.
 * Different HSM vendors may use different CKM/CKK/CKP values for the same algorithms.
 * Implementations map algorithm names to the vendor-specific constants.
 */
public interface PqcMechanismProfile {

    // Key generation mechanisms
    long ckmMlDsaKeyPairGen();
    long ckmMlKemKeyPairGen();

    // Sign/verify and encapsulate/decapsulate mechanisms
    long ckmMlDsa();
    long ckmMlKem();

    // Key types
    long ckkMlDsa();
    long ckkMlKem();

    // Attribute ID for parameter set selection
    long ckaParameterSet();

    /**
     * Resolve a key spec string like "ML-DSA-65" to a CKP parameter set value.
     */
    long resolveMlDsaParamSet(String keySpec) throws InvalidAlgorithmParameterException;

    /**
     * Resolve a key spec string like "ML-KEM-768" to a CKP parameter set value.
     */
    long resolveMlKemParamSet(String keySpec) throws InvalidAlgorithmParameterException;

    // SLH-DSA (FIPS 205)
    long ckmSlhDsaKeyPairGen();
    long ckmSlhDsa();
    long ckkSlhDsa();

    /**
     * Resolve a key spec string like "SLH-DSA-SHA2-128S" to a CKP parameter set value.
     */
    long resolveSlhDsaParamSet(String keySpec) throws InvalidAlgorithmParameterException;

    /**
     * Map a CKK key type value to an algorithm string (e.g., "RSA", "EC", "ML-DSA", "ML-KEM", "SLH-DSA").
     * Returns null if the key type is not recognized by this profile.
     */
    String algorithmForKeyType(long ckk);

    /**
     * Determine the key spec string (e.g., "ML-DSA-65") from CKK + CKP parameter set.
     * Used when reading existing keys from the token to display algorithm details.
     */
    String keySpecForParams(long ckk, long paramSet);

    /**
     * Whether this profile supports the given key spec string (ML-DSA, ML-KEM, SLH-DSA).
     */
    boolean supports(String keySpec);
}
