package com.composum.sling.platform.keycloak;

import org.apache.commons.io.IOUtils;
import org.keycloak.adapters.saml.SamlConfigResolver;
import org.keycloak.adapters.saml.SamlDeployment;
import org.keycloak.adapters.saml.config.parsers.DeploymentBuilder;
import org.keycloak.adapters.saml.config.parsers.ResourceLoader;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;

/**
 * Resolves the Keycloak SAML configuration. TODO: get this from Sling somehow.
 */
public class SlingSamlConfigResolver implements SamlConfigResolver {

    private static final Logger LOG = LoggerFactory.getLogger(SlingSamlConfigResolver.class);

    public static final String KEYCLOAK_SAML_XML = "/keycloak-saml.xml";

    @Override
    public SamlDeployment resolve(HttpFacade.Request request) {
        InputStream is = SlingSamlConfigResolver.class.getResourceAsStream(KEYCLOAK_SAML_XML);
        if (is == null) {
            throw new IllegalStateException("Not able to find the file /keycloak-saml.xml");
        }

        try {
            ResourceLoader loader = new ResourceLoader() {
                @Override
                public InputStream getResourceAsStream(String path) {
                    return SlingSamlConfigResolver.class.getResourceAsStream(path);
                }
            };

            return new DeploymentBuilder().build(is, loader);
        } catch (ParsingException e) {
            throw new IllegalStateException("Cannot load SAML deployment", e);
        } finally {
            IOUtils.closeQuietly(is);
        }
    }

}
