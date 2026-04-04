/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKK;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CryptokiE;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 * KeyStoreSpi backed by a PKCS#11 device via JackNJI11.
 */
public class Kimbo11ngKeyStoreSpi extends KeyStoreSpi {

    private static final Logger log = Logger.getLogger(Kimbo11ngKeyStoreSpi.class);

    private final CryptokiDevice device;
    private final Map<String, Kimbo11ngPrivateKey> privateKeys = new HashMap<>();
    private final Map<String, PublicKey> publicKeys = new HashMap<>();

    // Holds the last generated key pair handles for setKeyEntry labeling
    private long lastGeneratedPrivHandle = -1;
    private long lastGeneratedPubHandle = -1;

    public Kimbo11ngKeyStoreSpi(CryptokiDevice device) {
        this.device = device;
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws UnrecoverableKeyException {
        return privateKeys.get(alias);
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        return null;
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        // Try to find certificate on HSM by label
        try {
            long session = device.getOrOpenSession();
            CryptokiE ce = device.getCe();
            long[] handles = ce.FindObjects(session,
                    new CKA(CKA.CLASS, CKO.CERTIFICATE),
                    new CKA(CKA.LABEL, alias.getBytes("UTF-8")));
            if (handles != null && handles.length > 0) {
                log.debug("Certificate found for alias " + alias + " but not returning cert object");
            }
        } catch (Exception e) {
            log.debug("No certificate for alias " + alias + ": " + e.getMessage());
        }
        return null;
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        return new Date();
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) {
        if (key instanceof Kimbo11ngPrivateKey) {
            Kimbo11ngPrivateKey p11Key = (Kimbo11ngPrivateKey) key;
            try {
                long session = device.getOrOpenSession();
                CryptokiE ce = device.getCe();
                byte[] labelBytes = alias.getBytes("UTF-8");

                // Set label on private key
                ce.SetAttributeValue(session, p11Key.getObjectHandle(),
                        new CKA(CKA.LABEL, labelBytes));

                // Label the corresponding public key if we have its handle
                if (lastGeneratedPrivHandle == p11Key.getObjectHandle() && lastGeneratedPubHandle >= 0) {
                    ce.SetAttributeValue(session, lastGeneratedPubHandle,
                            new CKA(CKA.LABEL, labelBytes));
                }

                // Re-register with new alias
                Kimbo11ngPrivateKey relabeled = new Kimbo11ngPrivateKey(
                        p11Key.getObjectHandle(), p11Key.getAlgorithm(), alias, device);
                privateKeys.put(alias, relabeled);

                if (log.isDebugEnabled()) {
                    log.debug("Labeled key on HSM with alias: " + alias);
                }
            } catch (Exception e) {
                log.error("Failed to set key entry label: " + e.getMessage(), e);
            }
        }
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) {
        throw new UnsupportedOperationException("Cannot set raw key bytes on PKCS#11 token");
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) {
        log.debug("engineSetCertificateEntry called for alias " + alias + " - ignoring");
    }

    @Override
    public void engineDeleteEntry(String alias) {
        try {
            long session = device.getOrOpenSession();
            CryptokiE ce = device.getCe();
            byte[] labelBytes = alias.getBytes("UTF-8");

            // Find and delete private key
            long[] privHandles = ce.FindObjects(session,
                    new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
                    new CKA(CKA.LABEL, labelBytes));
            if (privHandles != null) {
                for (long h : privHandles) {
                    ce.DestroyObject(session, h);
                }
            }

            // Find and delete public key
            long[] pubHandles = ce.FindObjects(session,
                    new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
                    new CKA(CKA.LABEL, labelBytes));
            if (pubHandles != null) {
                for (long h : pubHandles) {
                    ce.DestroyObject(session, h);
                }
            }

            privateKeys.remove(alias);
            publicKeys.remove(alias);

            if (log.isDebugEnabled()) {
                log.debug("Deleted key entry: " + alias);
            }
        } catch (Exception e) {
            log.error("Failed to delete entry " + alias + ": " + e.getMessage(), e);
        }
    }

    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(privateKeys.keySet());
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return privateKeys.containsKey(alias);
    }

    @Override
    public int engineSize() {
        return privateKeys.size();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        return privateKeys.containsKey(alias);
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        return false;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        return null;
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) {
        // HSM manages persistence - no-op
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException {
        privateKeys.clear();
        publicKeys.clear();

        if (!device.isLoggedIn()) {
            if (password != null && password.length > 0) {
                try {
                    device.login(password);
                } catch (Exception e) {
                    throw new IOException("Failed to login to PKCS#11 token: " + e.getMessage(), e);
                }
            } else {
                log.debug("engineLoad called without password and not logged in - skipping key enumeration");
                return;
            }
        }

        try {
            enumerateKeys();
        } catch (Exception e) {
            throw new IOException("Failed to enumerate keys on PKCS#11 token: " + e.getMessage(), e);
        }
    }

    private void enumerateKeys() throws Exception {
        long session = device.getOrOpenSession();
        CryptokiE ce = device.getCe();

        // Find all private keys
        long[] privHandles = ce.FindObjects(session,
                new CKA(CKA.CLASS, CKO.PRIVATE_KEY));

        if (privHandles == null) {
            return;
        }

        for (long handle : privHandles) {
            try {
                CKA[] attrs = ce.GetAttributeValue(session, handle, CKA.LABEL, CKA.KEY_TYPE);
                byte[] labelBytes = attrs[0].getValue();
                Long keyTypeLong = attrs[1].getValueLong();
                long keyType = (keyTypeLong != null) ? keyTypeLong : 0L;

                String alias = (labelBytes != null) ? new String(labelBytes, "UTF-8").trim() : "key-" + handle;
                String algorithm;
                if (keyType == CKK.RSA) {
                    algorithm = "RSA";
                } else if (keyType == CKK.EC) {
                    algorithm = "EC";
                } else if (keyType == 0x4AL) {   // CKK_ML_DSA (PKCS#11 v3.2)
                    algorithm = "ML-DSA";
                } else if (keyType == 0x49L) {   // CKK_ML_KEM (PKCS#11 v3.2)
                    algorithm = "ML-KEM";
                } else if (keyType == 0x4BL) {   // CKK_SLH_DSA (PKCS#11 v3.2)
                    algorithm = "SLH-DSA";
                } else {
                    algorithm = "Unknown";
                }

                Kimbo11ngPrivateKey privKey = new Kimbo11ngPrivateKey(handle, algorithm, alias, device);
                privateKeys.put(alias, privKey);

                // Try to find matching public key
                try {
                    long[] pubHandles = ce.FindObjects(session,
                            new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
                            new CKA(CKA.LABEL, (labelBytes != null) ? labelBytes : new byte[0]));
                    if (pubHandles != null && pubHandles.length > 0) {
                        PublicKey pubKey;
                        if (keyType == CKK.RSA) {
                            pubKey = Kimbo11ngPublicKey.readRsaPublicKey(ce, session, pubHandles[0]);
                        } else if (keyType == CKK.EC) {
                            pubKey = Kimbo11ngPublicKey.readEcPublicKey(ce, session, pubHandles[0]);
                        } else if (keyType == 0x4AL) {   // CKK_ML_DSA
                            pubKey = Kimbo11ngPublicKey.readPqcPublicKey(ce, session, pubHandles[0], "ML-DSA");
                        } else if (keyType == 0x49L) {   // CKK_ML_KEM
                            pubKey = Kimbo11ngPublicKey.readPqcPublicKey(ce, session, pubHandles[0], "ML-KEM");
                        } else if (keyType == 0x4BL) {   // CKK_SLH_DSA
                            pubKey = Kimbo11ngPublicKey.readPqcPublicKey(ce, session, pubHandles[0], "SLH-DSA");
                        } else {
                            pubKey = null;
                        }
                        if (pubKey != null) {
                            publicKeys.put(alias, pubKey);
                        }
                    }
                } catch (Exception e) {
                    log.debug("Could not read public key for alias " + alias + ": " + e.getMessage());
                }

                if (log.isDebugEnabled()) {
                    log.debug("Loaded key: alias=" + alias + " algorithm=" + algorithm);
                }
            } catch (Exception e) {
                log.warn("Failed to process key handle " + handle + ": " + e.getMessage());
            }
        }
    }

    public void setLastGeneratedHandles(long privHandle, long pubHandle) {
        this.lastGeneratedPrivHandle = privHandle;
        this.lastGeneratedPubHandle = pubHandle;
    }

    public Map<String, Kimbo11ngPrivateKey> getPrivateKeys() {
        return privateKeys;
    }

    public Map<String, PublicKey> getPublicKeys() {
        return publicKeys;
    }

    public PublicKey getPublicKey(String alias) {
        return publicKeys.get(alias);
    }

    /**
     * Registers a newly generated key pair directly (bypasses engineLoad enumeration).
     */
    public void registerGeneratedKeyPair(String alias, long privHandle, String algorithm,
            PublicKey pubKey) {
        Kimbo11ngPrivateKey privKey = new Kimbo11ngPrivateKey(privHandle, algorithm, alias, device);
        privateKeys.put(alias, privKey);
        if (pubKey != null) {
            publicKeys.put(alias, pubKey);
        }
        if (log.isDebugEnabled()) {
            log.debug("Registered generated key pair with alias: " + alias);
        }
    }
}
