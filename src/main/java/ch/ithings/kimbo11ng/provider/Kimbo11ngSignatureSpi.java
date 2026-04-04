/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CryptokiE;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

/**
 * SignatureSpi implementation using JackNJI11 PKCS#11 backend.
 */
public abstract class Kimbo11ngSignatureSpi extends SignatureSpi {

    private static final Logger log = Logger.getLogger(Kimbo11ngSignatureSpi.class);

    private final long ckMechanism;
    private final boolean isEc;

    private CryptokiDevice device;
    private Kimbo11ngPrivateKey signingKey;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    protected Kimbo11ngSignatureSpi(long ckMechanism) {
        this(ckMechanism, false);
    }

    protected Kimbo11ngSignatureSpi(long ckMechanism, boolean isEc) {
        this.ckMechanism = ckMechanism;
        this.isEc = isEc;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof Kimbo11ngPrivateKey)) {
            throw new InvalidKeyException("Key must be a Kimbo11ngPrivateKey, got: " +
                    privateKey.getClass().getName());
        }
        signingKey = (Kimbo11ngPrivateKey) privateKey;
        device = signingKey.getDevice();
        buffer.reset();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        throw new InvalidKeyException("Verification not supported by Kimbo11ngSignatureSpi");
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        buffer.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        buffer.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (signingKey == null) {
            throw new SignatureException("Not initialized for signing");
        }
        try {
            long session = device.getOrOpenSession();
            CryptokiE ce = device.getCe();
            byte[] data = buffer.toByteArray();
            buffer.reset();

            synchronized (device) {
                ce.SignInit(session, new org.pkcs11.jacknji11.CKM(ckMechanism), signingKey.getObjectHandle());
                byte[] rawSig = ce.Sign(session, data);

                if (isEc) {
                    return convertRawEcdsaToDer(rawSig);
                }
                return rawSig;
            }
        } catch (Exception e) {
            throw new SignatureException("PKCS#11 signing failed: " + e.getMessage(), e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        throw new SignatureException("Verification not supported by Kimbo11ngSignatureSpi");
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new InvalidParameterException("setParameter not supported");
    }

    @Override
    @SuppressWarnings("deprecation")
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new InvalidParameterException("getParameter not supported");
    }

    /**
     * Convert raw PKCS#11 ECDSA signature (r || s) to DER-encoded ASN.1 SEQUENCE { INTEGER r, INTEGER s }.
     */
    private static byte[] convertRawEcdsaToDer(byte[] rawSig) throws SignatureException {
        if (rawSig == null || rawSig.length == 0 || rawSig.length % 2 != 0) {
            throw new SignatureException("Invalid raw ECDSA signature length: " +
                    (rawSig != null ? rawSig.length : 0));
        }
        int half = rawSig.length / 2;
        byte[] rBytes = new byte[half];
        byte[] sBytes = new byte[half];
        System.arraycopy(rawSig, 0, rBytes, 0, half);
        System.arraycopy(rawSig, half, sBytes, 0, half);

        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);

        try {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(r));
            v.add(new ASN1Integer(s));
            return new DERSequence(v).getEncoded();
        } catch (Exception e) {
            throw new SignatureException("Failed to DER-encode ECDSA signature: " + e.getMessage(), e);
        }
    }

    // ---- Inner subclasses for each algorithm ----

    public static class SHA1withRSA extends Kimbo11ngSignatureSpi {
        public SHA1withRSA() { super(CKM.SHA1_RSA_PKCS); }
    }

    public static class SHA256withRSA extends Kimbo11ngSignatureSpi {
        public SHA256withRSA() { super(CKM.SHA256_RSA_PKCS); }
    }

    public static class SHA384withRSA extends Kimbo11ngSignatureSpi {
        public SHA384withRSA() { super(CKM.SHA384_RSA_PKCS); }
    }

    public static class SHA512withRSA extends Kimbo11ngSignatureSpi {
        public SHA512withRSA() { super(CKM.SHA512_RSA_PKCS); }
    }

    public static class SHA1withECDSA extends Kimbo11ngSignatureSpi {
        public SHA1withECDSA() { super(CKM.ECDSA, true); }
    }

    public static class SHA256withECDSA extends Kimbo11ngSignatureSpi {
        public SHA256withECDSA() { super(CKM.ECDSA_SHA256, true); }
    }

    public static class SHA384withECDSA extends Kimbo11ngSignatureSpi {
        public SHA384withECDSA() { super(CKM.ECDSA_SHA384, true); }
    }

    public static class SHA512withECDSA extends Kimbo11ngSignatureSpi {
        public SHA512withECDSA() { super(CKM.ECDSA_SHA512, true); }
    }

    // ML-DSA (FIPS 204) — pure signature, no pre-hashing
    // CKM_ML_DSA = 0x1D (PKCS#11 v3.2)
    private static final long CKM_ML_DSA = 0x0000001DL;

    public static class MLDSA44 extends Kimbo11ngSignatureSpi {
        public MLDSA44() { super(CKM_ML_DSA); }
    }

    public static class MLDSA65 extends Kimbo11ngSignatureSpi {
        public MLDSA65() { super(CKM_ML_DSA); }
    }

    public static class MLDSA87 extends Kimbo11ngSignatureSpi {
        public MLDSA87() { super(CKM_ML_DSA); }
    }

    // SLH-DSA (FIPS 205) — pure signature, no pre-hashing
    // CKM_SLH_DSA = 0x2E (PKCS#11 v3.2)
    private static final long CKM_SLH_DSA = 0x0000002EL;

    public static class SLHDSA_SHA2_128S extends Kimbo11ngSignatureSpi {
        public SLHDSA_SHA2_128S() { super(CKM_SLH_DSA); }
    }

    public static class SLHDSA_SHAKE_128S extends Kimbo11ngSignatureSpi {
        public SLHDSA_SHAKE_128S() { super(CKM_SLH_DSA); }
    }

    public static class SLHDSA_SHA2_128F extends Kimbo11ngSignatureSpi {
        public SLHDSA_SHA2_128F() { super(CKM_SLH_DSA); }
    }

    public static class SLHDSA_SHAKE_128F extends Kimbo11ngSignatureSpi {
        public SLHDSA_SHAKE_128F() { super(CKM_SLH_DSA); }
    }

    public static class SLHDSA_SHA2_192S extends Kimbo11ngSignatureSpi {
        public SLHDSA_SHA2_192S() { super(CKM_SLH_DSA); }
    }

    public static class SLHDSA_SHAKE_192S extends Kimbo11ngSignatureSpi {
        public SLHDSA_SHAKE_192S() { super(CKM_SLH_DSA); }
    }

    public static class SLHDSA_SHA2_192F extends Kimbo11ngSignatureSpi {
        public SLHDSA_SHA2_192F() { super(CKM_SLH_DSA); }
    }

    public static class SLHDSA_SHAKE_192F extends Kimbo11ngSignatureSpi {
        public SLHDSA_SHAKE_192F() { super(CKM_SLH_DSA); }
    }

    public static class SLHDSA_SHA2_256S extends Kimbo11ngSignatureSpi {
        public SLHDSA_SHA2_256S() { super(CKM_SLH_DSA); }
    }

    public static class SLHDSA_SHAKE_256S extends Kimbo11ngSignatureSpi {
        public SLHDSA_SHAKE_256S() { super(CKM_SLH_DSA); }
    }

    public static class SLHDSA_SHA2_256F extends Kimbo11ngSignatureSpi {
        public SLHDSA_SHA2_256F() { super(CKM_SLH_DSA); }
    }

    public static class SLHDSA_SHAKE_256F extends Kimbo11ngSignatureSpi {
        public SLHDSA_SHAKE_256F() { super(CKM_SLH_DSA); }
    }
}
