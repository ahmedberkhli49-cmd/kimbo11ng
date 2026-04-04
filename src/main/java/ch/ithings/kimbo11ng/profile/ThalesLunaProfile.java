/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import java.security.InvalidAlgorithmParameterException;

/**
 * Scaffold profile for Thales Luna HSMs.
 * Luna 7.8.4+ supports ML-DSA and ML-KEM but uses vendor-specific CKM values
 * before full PKCS#11 v3.2 adoption.
 *
 * TODO: Populate with actual Thales Luna CKM/CKK constants when available.
 * See: https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/pkcs11/pkcs11_pqc.htm
 */
public class ThalesLunaProfile implements PqcMechanismProfile {

    private static final String NOT_YET = "Thales Luna PQC profile not yet populated. " +
            "Requires vendor-specific CKM values from Luna firmware 7.8.4+ documentation.";

    @Override public long ckmMlDsaKeyPairGen()  { throw new UnsupportedOperationException(NOT_YET); }
    @Override public long ckmMlKemKeyPairGen()  { throw new UnsupportedOperationException(NOT_YET); }
    @Override public long ckmMlDsa()            { throw new UnsupportedOperationException(NOT_YET); }
    @Override public long ckmMlKem()            { throw new UnsupportedOperationException(NOT_YET); }
    @Override public long ckkMlDsa()            { throw new UnsupportedOperationException(NOT_YET); }
    @Override public long ckkMlKem()            { throw new UnsupportedOperationException(NOT_YET); }
    @Override public long ckaParameterSet()     { throw new UnsupportedOperationException(NOT_YET); }
    @Override public long ckmSlhDsaKeyPairGen() { throw new UnsupportedOperationException(NOT_YET); }
    @Override public long ckmSlhDsa()           { throw new UnsupportedOperationException(NOT_YET); }
    @Override public long ckkSlhDsa()           { throw new UnsupportedOperationException(NOT_YET); }

    @Override
    public long resolveMlDsaParamSet(String keySpec) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(NOT_YET);
    }

    @Override
    public long resolveMlKemParamSet(String keySpec) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(NOT_YET);
    }

    @Override
    public long resolveSlhDsaParamSet(String keySpec) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(NOT_YET);
    }

    @Override
    public String algorithmForKeyType(long ckk) {
        return null; // Not yet mapped
    }

    @Override
    public String keySpecForParams(long ckk, long paramSet) {
        return null;
    }

    @Override
    public boolean supports(String keySpec) {
        return false; // Not yet functional
    }

    @Override
    public String toString() {
        return "ThalesLunaProfile (scaffold - not yet implemented)";
    }
}
