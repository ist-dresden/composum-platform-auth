package com.composum.sling.platform.keycloak;

import org.keycloak.adapters.saml.SamlSession;

import javax.jcr.Credentials;

/**
 * Credentials derived from a
 */
public class KeycloakCredentials implements Credentials {

    private final SamlSession samlSession;

    public KeycloakCredentials(SamlSession samlSession) {
        this.samlSession = samlSession;
    }

    public SamlSession getSamlSession() {
        return samlSession;
    }
}
