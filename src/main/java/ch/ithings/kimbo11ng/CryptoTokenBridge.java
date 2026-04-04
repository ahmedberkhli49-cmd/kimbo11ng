/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng;

import com.keyfactor.util.keys.CachingKeyStoreWrapper;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.util.Properties;

/**
 * Bridge interface that exposes protected BaseCryptoToken methods
 * to CryptoTokenImpl (which lives in a different package).
 * Implemented by Pkcs11NgCryptoToken (which extends BaseCryptoToken).
 */
public interface CryptoTokenBridge {
    void bridgeSetKeyStore(KeyStore ks) throws KeyStoreException;
    CachingKeyStoreWrapper bridgeGetKeyStore();
    void bridgeSetJCAProvider(Provider provider);
    void bridgeSetProperties(Properties properties);
    Properties bridgeGetProperties();
    void bridgeSetTokenName(String name);
    void bridgeSetId(int id);
}
