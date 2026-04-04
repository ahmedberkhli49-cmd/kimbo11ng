/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import org.pkcs11.jacknji11.CKK;

import java.security.InvalidAlgorithmParameterException;

/**
 * Default PQC mechanism profile using standard PKCS#11 v3.2 constants.
 * Compatible with softhsmv3 and any HSM implementing the OASIS PKCS#11 v3.2 specification.
 */
public class Pkcs11v32Profile implements PqcMechanismProfile {

    // CKM mechanism constants (PKCS#11 v3.2)
    private static final long CKM_ML_DSA_KEY_PAIR_GEN = 0x0000001CL;
    private static final long CKM_ML_DSA              = 0x0000001DL;
    private static final long CKM_ML_KEM_KEY_PAIR_GEN = 0x0000000FL;
    private static final long CKM_ML_KEM              = 0x00000017L;

    // CKM mechanism constants for SLH-DSA (PKCS#11 v3.2)
    private static final long CKM_SLH_DSA_KEY_PAIR_GEN = 0x0000002DL;
    private static final long CKM_SLH_DSA              = 0x0000002EL;

    // CKK key type constants
    private static final long CKK_ML_DSA  = 0x0000004AL;
    private static final long CKK_ML_KEM  = 0x00000049L;
    private static final long CKK_SLH_DSA = 0x0000004BL;

    // CKA attribute for parameter set
    private static final long CKA_PARAMETER_SET = 0x0000061DL;

    // ML-DSA parameter sets (FIPS 204)
    private static final long CKP_ML_DSA_44 = 1L;
    private static final long CKP_ML_DSA_65 = 2L;
    private static final long CKP_ML_DSA_87 = 3L;

    // ML-KEM parameter sets (FIPS 203)
    private static final long CKP_ML_KEM_512  = 1L;
    private static final long CKP_ML_KEM_768  = 2L;
    private static final long CKP_ML_KEM_1024 = 3L;

    // SLH-DSA parameter sets (FIPS 205)
    private static final long CKP_SLH_DSA_SHA2_128S  =  1L;
    private static final long CKP_SLH_DSA_SHAKE_128S =  2L;
    private static final long CKP_SLH_DSA_SHA2_128F  =  3L;
    private static final long CKP_SLH_DSA_SHAKE_128F =  4L;
    private static final long CKP_SLH_DSA_SHA2_192S  =  5L;
    private static final long CKP_SLH_DSA_SHAKE_192S =  6L;
    private static final long CKP_SLH_DSA_SHA2_192F  =  7L;
    private static final long CKP_SLH_DSA_SHAKE_192F =  8L;
    private static final long CKP_SLH_DSA_SHA2_256S  =  9L;
    private static final long CKP_SLH_DSA_SHAKE_256S = 10L;
    private static final long CKP_SLH_DSA_SHA2_256F  = 11L;
    private static final long CKP_SLH_DSA_SHAKE_256F = 12L;

    @Override public long ckmMlDsaKeyPairGen()  { return CKM_ML_DSA_KEY_PAIR_GEN; }
    @Override public long ckmMlKemKeyPairGen()  { return CKM_ML_KEM_KEY_PAIR_GEN; }
    @Override public long ckmMlDsa()            { return CKM_ML_DSA; }
    @Override public long ckmMlKem()            { return CKM_ML_KEM; }
    @Override public long ckkMlDsa()            { return CKK_ML_DSA; }
    @Override public long ckkMlKem()            { return CKK_ML_KEM; }
    @Override public long ckaParameterSet()     { return CKA_PARAMETER_SET; }
    @Override public long ckmSlhDsaKeyPairGen() { return CKM_SLH_DSA_KEY_PAIR_GEN; }
    @Override public long ckmSlhDsa()           { return CKM_SLH_DSA; }
    @Override public long ckkSlhDsa()           { return CKK_SLH_DSA; }

    @Override
    public long resolveMlDsaParamSet(String keySpec) throws InvalidAlgorithmParameterException {
        String normalized = keySpec.toUpperCase().replace("-", "").replace("_", "");
        if (normalized.endsWith("44")) return CKP_ML_DSA_44;
        if (normalized.endsWith("65")) return CKP_ML_DSA_65;
        if (normalized.endsWith("87")) return CKP_ML_DSA_87;
        throw new InvalidAlgorithmParameterException(
                "Unknown ML-DSA parameter set in: " + keySpec + " (expected ML-DSA-44, ML-DSA-65, or ML-DSA-87)");
    }

    @Override
    public long resolveMlKemParamSet(String keySpec) throws InvalidAlgorithmParameterException {
        String normalized = keySpec.toUpperCase().replace("-", "").replace("_", "");
        if (normalized.endsWith("512"))  return CKP_ML_KEM_512;
        if (normalized.endsWith("768"))  return CKP_ML_KEM_768;
        if (normalized.endsWith("1024")) return CKP_ML_KEM_1024;
        throw new InvalidAlgorithmParameterException(
                "Unknown ML-KEM parameter set in: " + keySpec + " (expected ML-KEM-512, ML-KEM-768, or ML-KEM-1024)");
    }

    @Override
    public long resolveSlhDsaParamSet(String keySpec) throws InvalidAlgorithmParameterException {
        // Normalize: "SLH-DSA-SHA2-128S" -> "SLHDSASHA2128S", "SLH-DSA-SHAKE-128F" -> "SLHDSASHAKE128F"
        String normalized = keySpec.toUpperCase().replace("-", "").replace("_", "");
        if (normalized.endsWith("SHA2128S"))  return CKP_SLH_DSA_SHA2_128S;
        if (normalized.endsWith("SHAKE128S")) return CKP_SLH_DSA_SHAKE_128S;
        if (normalized.endsWith("SHA2128F"))  return CKP_SLH_DSA_SHA2_128F;
        if (normalized.endsWith("SHAKE128F")) return CKP_SLH_DSA_SHAKE_128F;
        if (normalized.endsWith("SHA2192S"))  return CKP_SLH_DSA_SHA2_192S;
        if (normalized.endsWith("SHAKE192S")) return CKP_SLH_DSA_SHAKE_192S;
        if (normalized.endsWith("SHA2192F"))  return CKP_SLH_DSA_SHA2_192F;
        if (normalized.endsWith("SHAKE192F")) return CKP_SLH_DSA_SHAKE_192F;
        if (normalized.endsWith("SHA2256S"))  return CKP_SLH_DSA_SHA2_256S;
        if (normalized.endsWith("SHAKE256S")) return CKP_SLH_DSA_SHAKE_256S;
        if (normalized.endsWith("SHA2256F"))  return CKP_SLH_DSA_SHA2_256F;
        if (normalized.endsWith("SHAKE256F")) return CKP_SLH_DSA_SHAKE_256F;
        throw new InvalidAlgorithmParameterException(
                "Unknown SLH-DSA parameter set in: " + keySpec +
                " (expected e.g. SLH-DSA-SHA2-128S, SLH-DSA-SHAKE-256F)");
    }

    @Override
    public String algorithmForKeyType(long ckk) {
        if (ckk == CKK.RSA)     return "RSA";
        if (ckk == CKK.EC)      return "EC";
        if (ckk == CKK_ML_DSA)  return "ML-DSA";
        if (ckk == CKK_ML_KEM)  return "ML-KEM";
        if (ckk == CKK_SLH_DSA) return "SLH-DSA";
        return null;
    }

    @Override
    public String keySpecForParams(long ckk, long paramSet) {
        if (ckk == CKK_ML_DSA) {
            if (paramSet == CKP_ML_DSA_44) return "ML-DSA-44";
            if (paramSet == CKP_ML_DSA_87) return "ML-DSA-87";
            return "ML-DSA-65"; // default
        }
        if (ckk == CKK_ML_KEM) {
            if (paramSet == CKP_ML_KEM_512)  return "ML-KEM-512";
            if (paramSet == CKP_ML_KEM_1024) return "ML-KEM-1024";
            return "ML-KEM-768"; // default
        }
        if (ckk == CKK_SLH_DSA) {
            if (paramSet == CKP_SLH_DSA_SHA2_128S)  return "SLH-DSA-SHA2-128S";
            if (paramSet == CKP_SLH_DSA_SHAKE_128S) return "SLH-DSA-SHAKE-128S";
            if (paramSet == CKP_SLH_DSA_SHA2_128F)  return "SLH-DSA-SHA2-128F";
            if (paramSet == CKP_SLH_DSA_SHAKE_128F) return "SLH-DSA-SHAKE-128F";
            if (paramSet == CKP_SLH_DSA_SHA2_192S)  return "SLH-DSA-SHA2-192S";
            if (paramSet == CKP_SLH_DSA_SHAKE_192S) return "SLH-DSA-SHAKE-192S";
            if (paramSet == CKP_SLH_DSA_SHA2_192F)  return "SLH-DSA-SHA2-192F";
            if (paramSet == CKP_SLH_DSA_SHAKE_192F) return "SLH-DSA-SHAKE-192F";
            if (paramSet == CKP_SLH_DSA_SHA2_256S)  return "SLH-DSA-SHA2-256S";
            if (paramSet == CKP_SLH_DSA_SHAKE_256S) return "SLH-DSA-SHAKE-256S";
            if (paramSet == CKP_SLH_DSA_SHA2_256F)  return "SLH-DSA-SHA2-256F";
            if (paramSet == CKP_SLH_DSA_SHAKE_256F) return "SLH-DSA-SHAKE-256F";
            return "SLH-DSA-SHA2-128S"; // default
        }
        return null;
    }

    @Override
    public boolean supports(String keySpec) {
        if (keySpec == null) return false;
        String upper = keySpec.toUpperCase();
        return upper.startsWith("ML-DSA")  || upper.startsWith("MLDSA")  ||
               upper.startsWith("ML-KEM")  || upper.startsWith("MLKEM")  ||
               upper.startsWith("SLH-DSA") || upper.startsWith("SLHDSA");
    }

    @Override
    public String toString() {
        return "Pkcs11v32Profile (OASIS PKCS#11 v3.2)";
    }
}
