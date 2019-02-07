package com.composum.sling.platform.keycloak;

import org.apache.sling.auth.core.spi.AuthenticationFeedbackHandler;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.DefaultAuthenticationFeedbackHandler;
import org.keycloak.adapters.saml.SamlConfigResolver;
import org.keycloak.adapters.saml.SamlDeploymentContext;
import org.keycloak.adapters.spi.InMemorySessionIdMapper;
import org.keycloak.adapters.spi.SessionIdMapper;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Authentication handler that uses Keycloak to perform authentication for us, which is handling the the nitty gritty details of login via various providers for us. We use SAML to interface Keycloak, since that seems simpler to include than using OpenID.
 *
 * @see "https://www.keycloak.org/docs-api/4.8/javadocs/index.html"
 */
//@Component(name = "com.composum.sling.platform.keycloak.KeycloakAuthenticationHandler",
//        property = {
//                AuthenticationHandler.TYPE_PROPERTY + "=" + KeycloakAuthenticationHandler.KEYCLOAK_AUTH,
//                AuthenticationHandler.PATH_PROPERTY + "=/content/ist/restricted",
//                AuthenticationHandler.PATH_PROPERTY + "=/saml"
//        },
//        service = {AuthenticationHandler.class, AuthenticationFeedbackHandler.class},
//        immediate = true)
public class KeycloakAuthenticationHandler extends DefaultAuthenticationFeedbackHandler implements AuthenticationHandler {

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakAuthenticationHandler.class);

    public static final String KEYCLOAK_AUTH = "Keycloak";

    private ComponentContext context;

    protected SamlDeploymentContext deploymentContext;

    protected SessionIdMapper idMapper;

    @Activate
    private void activate(final ComponentContext context) {
        this.context = context;
        SamlConfigResolver configResolver = new SlingSamlConfigResolver();
        deploymentContext = new SamlDeploymentContext(configResolver);
        idMapper = new InMemorySessionIdMapper();
    }


    @Override
    public AuthenticationInfo extractCredentials(HttpServletRequest request, HttpServletResponse response) {
        if (0 == 0)
            throw new UnsupportedOperationException("Not implemented yet: KeycloakAuthenticationHandler.extractCredentials");
        // TODO hps 2019-02-06 implement KeycloakAuthenticationHandler.extractCredentials
        AuthenticationInfo result = null;
        return result;
    }

    @Override
    public boolean requestCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (0 == 0)
            throw new UnsupportedOperationException("Not implemented yet: KeycloakAuthenticationHandler.requestCredentials");
        // TODO hps 2019-02-06 implement KeycloakAuthenticationHandler.requestCredentials
        boolean result = false;
        return result;
    }

    @Override
    public void dropCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (0 == 0)
            throw new UnsupportedOperationException("Not implemented yet: KeycloakAuthenticationHandler.dropCredentials");
        // TODO hps 2019-02-06 implement KeycloakAuthenticationHandler.dropCredentials

    }
}
