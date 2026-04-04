/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import java.security.PrivateKey;

/**
 * PrivateKey handle wrapping a PKCS#11 object handle.
 * The actual key material never leaves the HSM.
 */
public class Kimbo11ngPrivateKey implements PrivateKey {

    private static final long serialVersionUID = 1L;

    private final long objectHandle;
    private final String algorithm;
    private final String alias;
    private final transient CryptokiDevice device;

    public Kimbo11ngPrivateKey(long objectHandle, String algorithm, String alias, CryptokiDevice device) {
        this.objectHandle = objectHandle;
        this.algorithm = algorithm;
        this.alias = alias;
        this.device = device;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return "PKCS#11";
    }

    @Override
    public byte[] getEncoded() {
        // Private keys on HSM are not extractable
        return null;
    }

    public long getObjectHandle() {
        return objectHandle;
    }

    public String getAlias() {
        return alias;
    }

    public CryptokiDevice getDevice() {
        return device;
    }

    @Override
    public String toString() {
        return "Kimbo11ngPrivateKey{alias=" + alias + " algorithm=" + algorithm +
                " handle=" + objectHandle + "}";
    }
}
