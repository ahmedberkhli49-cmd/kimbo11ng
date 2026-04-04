/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import ch.ithings.kimbo11ng.provider.CryptokiDevice;
import org.apache.log4j.Logger;

import java.util.Properties;

/**
 * Resolves which PqcMechanismProfile to use for a given HSM.
 *
 * Resolution order:
 * 1. Explicit property: {@code kimbo11ng.pqc.profile=pkcs11v32|thales-luna|<FQCN>}
 * 2. Auto-detection via C_GetMechanismList (future)
 * 3. Default: Pkcs11v32Profile
 */
public final class ProfileResolver {

    private static final Logger log = Logger.getLogger(ProfileResolver.class);

    public static final String PROFILE_PROPERTY = "kimbo11ng.pqc.profile";

    private ProfileResolver() {
    }

    /**
     * Resolve the PQC mechanism profile from configuration and/or device probing.
     *
     * @param properties crypto token properties (may contain kimbo11ng.pqc.profile)
     * @param device     the initialized CryptokiDevice (for future auto-detection)
     * @return the resolved profile, never null
     */
    public static PqcMechanismProfile resolve(Properties properties, CryptokiDevice device) {
        String profileName = properties != null ? properties.getProperty(PROFILE_PROPERTY) : null;

        if (profileName != null && !profileName.isEmpty()) {
            PqcMechanismProfile profile = fromName(profileName.trim());
            if (profile != null) {
                log.info("Using PQC mechanism profile: " + profile + " (from property)");
                return profile;
            }
            log.warn("Unknown PQC profile '" + profileName + "', falling back to Pkcs11v32Profile");
        }

        // Future: probe device.getCe().GetMechanismList() for known PQC CKM values
        // and auto-select vendor profile based on which mechanisms are present.

        PqcMechanismProfile defaultProfile = new Pkcs11v32Profile();
        if (log.isDebugEnabled()) {
            log.debug("Using default PQC mechanism profile: " + defaultProfile);
        }
        return defaultProfile;
    }

    private static PqcMechanismProfile fromName(String name) {
        switch (name.toLowerCase()) {
            case "pkcs11v32":
            case "pkcs11-v32":
            case "standard":
                return new Pkcs11v32Profile();
            case "thales-luna":
            case "thales":
            case "luna":
                return new ThalesLunaProfile();
            default:
                // Try as FQCN
                try {
                    Class<?> clazz = Class.forName(name);
                    return (PqcMechanismProfile) clazz.getDeclaredConstructor().newInstance();
                } catch (Exception e) {
                    log.warn("Could not load PQC profile class: " + name + ": " + e.getMessage());
                    return null;
                }
        }
    }
}
