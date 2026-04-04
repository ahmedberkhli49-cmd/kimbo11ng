/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKK;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CryptokiE;
import org.pkcs11.jacknji11.LongRef;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

/**
 * KeyPairGeneratorSpi for RSA and EC key generation on PKCS#11 HSM.
 */
public abstract class Kimbo11ngKeyPairGeneratorSpi extends KeyPairGeneratorSpi {

    private static final Logger log = Logger.getLogger(Kimbo11ngKeyPairGeneratorSpi.class);

    protected final CryptokiDevice device;
    protected final Kimbo11ngProvider provider;

    protected Kimbo11ngKeyPairGeneratorSpi(CryptokiDevice device, Kimbo11ngProvider provider) {
        this.device = device;
        this.provider = provider;
    }

    // ---- RSA subclass ----

    public static class RSA extends Kimbo11ngKeyPairGeneratorSpi {

        private int keySize = 2048;

        public RSA(CryptokiDevice device, Kimbo11ngProvider provider) {
            super(device, provider);
        }

        @Override
        public void initialize(int keysize, SecureRandom random) {
            this.keySize = keysize;
        }

        @Override
        public void initialize(AlgorithmParameterSpec params, SecureRandom random)
                throws InvalidAlgorithmParameterException {
            throw new InvalidAlgorithmParameterException("Use initialize(int) for RSA");
        }

        @Override
        public KeyPair generateKeyPair() {
            try {
                long session = device.getOrOpenSession();
                CryptokiE ce = device.getCe();

                CKA[] pubTemplate = {
                        new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
                        new CKA(CKA.KEY_TYPE, CKK.RSA),
                        new CKA(CKA.MODULUS_BITS, (long) keySize),
                        new CKA(CKA.PUBLIC_EXPONENT, BigInteger.valueOf(65537).toByteArray()),
                        new CKA(CKA.TOKEN, true),
                        new CKA(CKA.VERIFY, true),
                        new CKA(CKA.ENCRYPT, true),
                        new CKA(CKA.WRAP, true)
                };

                CKA[] privTemplate = {
                        new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
                        new CKA(CKA.KEY_TYPE, CKK.RSA),
                        new CKA(CKA.TOKEN, true),
                        new CKA(CKA.PRIVATE, true),
                        new CKA(CKA.SENSITIVE, true),
                        new CKA(CKA.EXTRACTABLE, false),
                        new CKA(CKA.SIGN, true),
                        new CKA(CKA.DECRYPT, true),
                        new CKA(CKA.UNWRAP, true)
                };

                LongRef pubRef = new LongRef();
                LongRef privRef = new LongRef();

                synchronized (device) {
                    ce.GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN),
                            pubTemplate, privTemplate, pubRef, privRef);
                }

                long pubHandle = pubRef.value();
                long privHandle = privRef.value();

                provider.setLastGeneratedHandles(privHandle, pubHandle);

                Kimbo11ngPrivateKey privKey = new Kimbo11ngPrivateKey(privHandle, "RSA",
                        "generated-" + privHandle, device);
                java.security.PublicKey pubKey = Kimbo11ngPublicKey.readRsaPublicKey(ce, session, pubHandle);

                if (log.isDebugEnabled()) {
                    log.debug("Generated RSA-" + keySize + " key pair: privHandle=" +
                            privHandle + " pubHandle=" + pubHandle);
                }

                return new KeyPair(pubKey, privKey);
            } catch (Exception e) {
                throw new RuntimeException("Failed to generate RSA key pair on HSM: " + e.getMessage(), e);
            }
        }
    }

    // ---- EC subclass ----

    public static class EC extends Kimbo11ngKeyPairGeneratorSpi {

        private byte[] ecParamsDer;
        private String curveName;

        public EC(CryptokiDevice device, Kimbo11ngProvider provider) {
            super(device, provider);
        }

        @Override
        public void initialize(int keysize, SecureRandom random) {
            switch (keysize) {
                case 256: initCurve("P-256"); break;
                case 384: initCurve("P-384"); break;
                case 521: initCurve("P-521"); break;
                default:  initCurve("P-256");
            }
        }

        @Override
        public void initialize(AlgorithmParameterSpec params, SecureRandom random)
                throws InvalidAlgorithmParameterException {
            if (params instanceof ECGenParameterSpec) {
                initCurve(((ECGenParameterSpec) params).getName());
            } else {
                throw new InvalidAlgorithmParameterException(
                        "Expected ECGenParameterSpec, got: " + params.getClass().getName());
            }
        }

        private void initCurve(String name) {
            this.curveName = name;
            try {
                String oidStr = resolveOid(name);
                ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(oidStr);
                this.ecParamsDer = oid.getEncoded();
            } catch (Exception e) {
                throw new RuntimeException("Failed to encode EC params for curve: " + name, e);
            }
        }

        private String resolveOid(String name) {
            switch (name.toUpperCase().replace("-", "").replace("_", "")) {
                case "P256": case "SECP256R1": case "PRIME256V1": return "1.2.840.10045.3.1.7";
                case "P384": case "SECP384R1": return "1.3.132.0.34";
                case "P521": case "SECP521R1": return "1.3.132.0.35";
                case "SECP256K1": return "1.3.132.0.10";
                case "BRAINPOOLP256R1": return "1.3.36.3.3.2.8.1.1.7";
                case "BRAINPOOLP384R1": return "1.3.36.3.3.2.8.1.1.11";
                case "BRAINPOOLP512R1": return "1.3.36.3.3.2.8.1.1.13";
                default:
                    org.bouncycastle.asn1.x9.X9ECParameters x9 = ECNamedCurveTable.getByName(name);
                    if (x9 != null) {
                        ASN1ObjectIdentifier oid = ECNamedCurveTable.getOID(name);
                        if (oid != null) return oid.getId();
                    }
                    return name;
            }
        }

        @Override
        public KeyPair generateKeyPair() {
            if (ecParamsDer == null) {
                initialize(256, null);
            }
            try {
                long session = device.getOrOpenSession();
                CryptokiE ce = device.getCe();

                CKA[] pubTemplate = {
                        new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
                        new CKA(CKA.KEY_TYPE, CKK.EC),
                        new CKA(CKA.EC_PARAMS, ecParamsDer),
                        new CKA(CKA.TOKEN, true),
                        new CKA(CKA.VERIFY, true),
                        new CKA(CKA.ENCRYPT, false)
                };

                CKA[] privTemplate = {
                        new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
                        new CKA(CKA.KEY_TYPE, CKK.EC),
                        new CKA(CKA.TOKEN, true),
                        new CKA(CKA.PRIVATE, true),
                        new CKA(CKA.SENSITIVE, true),
                        new CKA(CKA.EXTRACTABLE, false),
                        new CKA(CKA.SIGN, true)
                };

                LongRef pubRef = new LongRef();
                LongRef privRef = new LongRef();

                synchronized (device) {
                    ce.GenerateKeyPair(session, new CKM(CKM.EC_KEY_PAIR_GEN),
                            pubTemplate, privTemplate, pubRef, privRef);
                }

                long pubHandle = pubRef.value();
                long privHandle = privRef.value();

                provider.setLastGeneratedHandles(privHandle, pubHandle);

                Kimbo11ngPrivateKey privKey = new Kimbo11ngPrivateKey(privHandle, "EC",
                        "generated-" + privHandle, device);
                java.security.PublicKey pubKey = Kimbo11ngPublicKey.readEcPublicKey(ce, session, pubHandle);

                if (log.isDebugEnabled()) {
                    log.debug("Generated EC key pair (curve=" + curveName + "): privHandle=" +
                            privHandle + " pubHandle=" + pubHandle);
                }

                return new KeyPair(pubKey, privKey);
            } catch (Exception e) {
                throw new RuntimeException("Failed to generate EC key pair on HSM: " + e.getMessage(), e);
            }
        }
    }
}
