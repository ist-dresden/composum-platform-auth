package com.composum.platform.auth.keycloak;

import org.junit.Test;
import org.keycloak.adapters.saml.SamlDeployment;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

class SlingSamlConfigResolverTest {

    @Test
    void resolve() {
        SamlDeployment deployment = new SlingSamlConfigResolver().resolve(null);
        assertNotNull(deployment);
        // this is a changed property, so if that's true we have actually read the config file
        assertTrue(deployment.isAutodetectBearerOnly());
    }
}
