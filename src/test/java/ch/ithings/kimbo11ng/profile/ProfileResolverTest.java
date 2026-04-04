/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

class ProfileResolverTest {

    // CryptokiDevice is unused in the current resolve() implementation
    // (reserved for future auto-detection), so null is safe here.

    @Test
    void resolve_nullProperties_returnsDefault() {
        PqcMechanismProfile p = ProfileResolver.resolve(null, null);
        assertInstanceOf(Pkcs11v32Profile.class, p);
    }

    @Test
    void resolve_emptyProperties_returnsDefault() {
        PqcMechanismProfile p = ProfileResolver.resolve(new Properties(), null);
        assertInstanceOf(Pkcs11v32Profile.class, p);
    }

    @ParameterizedTest
    @ValueSource(strings = {"pkcs11v32", "pkcs11-v32", "standard", "STANDARD", "Pkcs11v32"})
    void resolve_pkcs11v32Aliases(String profileName) {
        Properties props = new Properties();
        props.setProperty(ProfileResolver.PROFILE_PROPERTY, profileName);
        assertInstanceOf(Pkcs11v32Profile.class, ProfileResolver.resolve(props, null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"thales-luna", "thales", "luna", "Thales-Luna"})
    void resolve_thalesLunaAliases(String profileName) {
        Properties props = new Properties();
        props.setProperty(ProfileResolver.PROFILE_PROPERTY, profileName);
        assertInstanceOf(ThalesLunaProfile.class, ProfileResolver.resolve(props, null));
    }

    @Test
    void resolve_fqcn_loadsClass() {
        Properties props = new Properties();
        props.setProperty(ProfileResolver.PROFILE_PROPERTY,
                "ch.ithings.kimbo11ng.profile.Pkcs11v32Profile");
        assertInstanceOf(Pkcs11v32Profile.class, ProfileResolver.resolve(props, null));
    }

    @Test
    void resolve_unknownName_fallsBackToDefault() {
        Properties props = new Properties();
        props.setProperty(ProfileResolver.PROFILE_PROPERTY, "no-such-profile");
        // Unknown name → warn + fall back to Pkcs11v32Profile
        assertInstanceOf(Pkcs11v32Profile.class, ProfileResolver.resolve(props, null));
    }

    @Test
    void resolve_unknownFqcn_fallsBackToDefault() {
        Properties props = new Properties();
        props.setProperty(ProfileResolver.PROFILE_PROPERTY,
                "com.example.nonexistent.Profile");
        assertInstanceOf(Pkcs11v32Profile.class, ProfileResolver.resolve(props, null));
    }
}
