package com.composum.platform.auth.keycloak;

import org.apache.jackrabbit.JcrConstants;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.settings.SlingSettingsService;
import org.keycloak.adapters.saml.SamlConfigResolver;
import org.keycloak.adapters.saml.SamlDeployment;
import org.keycloak.adapters.saml.config.parsers.DeploymentBuilder;
import org.keycloak.adapters.saml.config.parsers.ResourceLoader;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.InputStream;
import java.util.Set;

/**
 * Resolves the Keycloak SAML configuration from JCR.
 */
@Component(service = SamlConfigResolver.class, immediate = true)
public class SlingSamlConfigResolver implements SamlConfigResolver {

    private static final Logger LOG = LoggerFactory.getLogger(SlingSamlConfigResolver.class);

    public static final String AUTH_CONFIG_ROOT = "/conf/composum/platform/auth";
    public static final String KEYCLOAK_SAML_XML = "keycloak-saml.xml";

    @Reference
    private SlingSettingsService slingSettings;

    @Reference
    protected ResourceResolverFactory resolverFactory;

    private transient SamlDeployment samlDeployment;

    @Activate
    @Modified
    protected void activate() {
        samlDeployment = null;
    }

    @Override
    public SamlDeployment resolve(HttpFacade.Request request) {
        if (samlDeployment == null) {
            try (@Nonnull final ResourceResolver adminResolver = resolverFactory.getServiceResourceResolver(null)) {

                Resource configuration = resolveConfigFile(adminResolver);
                if (configuration != null) {

                    ResourceLoader loader = new ResourceLoader() {
                        @Override
                        public InputStream getResourceAsStream(String path) {
                            Resource configuration, content;
                            InputStream inputStream;
                            if ((configuration = adminResolver.getResource(path)) == null
                                    || (content = configuration.getChild(JcrConstants.JCR_CONTENT)) == null
                                    || (inputStream = content.adaptTo(InputStream.class)) == null) {
                                throw new IllegalStateException("Not able to load config resource " + path);
                            }
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Reading " + content.getPath());
                            }
                            return inputStream;
                        }
                    };

                    try (InputStream inputStream = loader.getResourceAsStream(configuration.getPath())) {

                        samlDeployment = new DeploymentBuilder().build(inputStream, loader);

                    } catch (ParsingException | IOException ex) {
                        LOG.error(ex.getMessage(), ex);
                        throw new IllegalStateException("Cannot load SAML deployment", ex);
                    }

                } else {
                    LOG.warn("no AUTH configuration found");
                }
            } catch (LoginException ex) {
                LOG.error(ex.getMessage(), ex);
                throw new IllegalStateException("Cannot access SAML deployment", ex);
            }
        }
        return samlDeployment;
    }

    protected Resource resolveConfigFile(ResourceResolver resolver) {
        String path;
        Resource configFile;
        Set<String> runmodes = slingSettings.getRunModes();
        for (String runmode : runmodes) {
            path = AUTH_CONFIG_ROOT + "/auth." + runmode + "/" + KEYCLOAK_SAML_XML;
            configFile = resolver.getResource(path);
            if (LOG.isDebugEnabled()) {
                LOG.debug("try '{}': {}", path, configFile);
            }
            if (configFile != null) {
                return configFile;
            }
        }
        path = AUTH_CONFIG_ROOT + "/" + KEYCLOAK_SAML_XML;
        configFile = resolver.getResource(path);
        if (LOG.isDebugEnabled()) {
            LOG.debug("try '{}': {}", path, configFile);
        }
        return configFile;
    }
}
