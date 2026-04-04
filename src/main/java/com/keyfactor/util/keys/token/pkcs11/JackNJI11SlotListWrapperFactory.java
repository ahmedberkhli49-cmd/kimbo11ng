/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package com.keyfactor.util.keys.token.pkcs11;

import ch.ithings.kimbo11ng.slot.SlotListWrapper;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * PKCS11SlotListWrapperFactory using JackNJI11 — EJBCA SPI entry point.
 *
 * This FQN is registered in META-INF/services and must not be moved.
 * Delegates to {@link SlotListWrapper}.
 * Priority 2 beats SunP11SlotListWrapperFactory's priority of 1.
 */
public class JackNJI11SlotListWrapperFactory implements PKCS11SlotListWrapperFactory {

    private static final Logger log = Logger.getLogger(JackNJI11SlotListWrapperFactory.class);

    private static final Map<String, SlotListWrapper> instanceCache = new HashMap<>();

    @Override
    public int getPriority() {
        return 2;
    }

    @Override
    public synchronized PKCS11SlotListWrapper getInstance(File file) {
        try {
            String canonicalPath = file.getCanonicalPath();
            SlotListWrapper wrapper = instanceCache.get(canonicalPath);
            if (wrapper == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Creating new SlotListWrapper for: " + canonicalPath);
                }
                wrapper = new SlotListWrapper(canonicalPath);
                instanceCache.put(canonicalPath, wrapper);
            }
            return wrapper;
        } catch (IOException e) {
            log.error("Failed to get canonical path for: " + file, e);
            return new SlotListWrapper(file.getAbsolutePath());
        }
    }
}
