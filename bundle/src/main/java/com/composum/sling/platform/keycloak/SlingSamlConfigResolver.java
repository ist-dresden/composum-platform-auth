package com.composum.sling.platform.keycloak;

import org.keycloak.adapters.saml.SamlConfigResolver;
import org.keycloak.adapters.saml.SamlDeployment;
import org.keycloak.adapters.saml.config.parsers.DeploymentBuilder;
import org.keycloak.adapters.saml.config.parsers.ResourceLoader;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.saml.common.exceptions.ParsingException;

import java.io.IOException;
import java.io.InputStream;

/**
 * Resolves the Keycloak SAML configuration. TODO: get this from Sling somehow.
 */
public class SlingSamlConfigResolver implements SamlConfigResolver {

    @Override
    public SamlDeployment resolve(HttpFacade.Request request) {
        InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream("/keycloak-saml.xml");
        if (is == null) {
            throw new IllegalStateException("Not able to find the file /keycloak-saml.xml");
        }

        try {
            is.close();

            ResourceLoader loader = new ResourceLoader() {
                @Override
                public InputStream getResourceAsStream(String path) {
                    return Thread.currentThread().getContextClassLoader().getResourceAsStream(path);
                }
            };

            return new DeploymentBuilder().build(is, loader);
        } catch (ParsingException | IOException e) {
            throw new IllegalStateException("Cannot load SAML deployment", e);
        }
    }

}
