package com.composum.platform.auth.keycloak;

import org.apache.commons.io.IOUtils;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.keycloak.adapters.saml.SamlConfigResolver;
import org.keycloak.adapters.saml.SamlDeployment;
import org.keycloak.adapters.saml.config.parsers.DeploymentBuilder;
import org.keycloak.adapters.saml.config.parsers.ResourceLoader;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.InputStream;

/**
 * Resolves the Keycloak SAML configuration from JCR.
 */
@Component(service = SamlConfigResolver.class, immediate = true)
public class SlingSamlConfigResolver implements SamlConfigResolver {

    private static final Logger LOG = LoggerFactory.getLogger(SlingSamlConfigResolver.class);

    public static final String KEYCLOAK_SAML_XML = "/conf/composum/platform/auth/keycloak-saml.xml";
    public static final String JCR_CONTENT_SUFFIX = "/jcr:content";

    @Reference
    protected ResourceResolverFactory resolverFactory;

    @Override
    public SamlDeployment resolve(HttpFacade.Request request) {
        InputStream configInputStream = null;
        try (@Nonnull ResourceResolver adminResolver = resolverFactory.getAdministrativeResourceResolver(null)) {

            Resource configuration = adminResolver.getResource(KEYCLOAK_SAML_XML + JCR_CONTENT_SUFFIX);
            configInputStream = configuration.adaptTo(InputStream.class);
            if (configInputStream == null) {
                throw new IllegalStateException("Not able to find the resource " + KEYCLOAK_SAML_XML + JCR_CONTENT_SUFFIX);
            }

            ResourceLoader loader = new ResourceLoader() {
                @Override
                public InputStream getResourceAsStream(String path) {
                    Resource subresource = configuration.getChild(path + JCR_CONTENT_SUFFIX);
                    LOG.debug("Reading " + subresource);
                    return subresource.adaptTo(InputStream.class);
                }
            };

            return new DeploymentBuilder().build(configInputStream, loader);
        } catch (ParsingException | LoginException e) {
            throw new IllegalStateException("Cannot load SAML deployment", e);
        } finally {
            IOUtils.closeQuietly(configInputStream);
        }
    }

}
