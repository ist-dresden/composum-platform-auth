package com.composum.sling.platform.keycloak;

import org.keycloak.adapters.saml.SamlDeployment;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SlingSamlConfigResolverTest {

    @org.junit.jupiter.api.Test
    void resolve() {
        SamlDeployment deployment = new SlingSamlConfigResolver().resolve(null);
        assertNotNull(deployment);
        // this is a changed property, so if that's true we have actually read the config file
        assertTrue(deployment.isAutodetectBearerOnly());
    }
}
