package com.composum.platform.auth.keycloak;

import org.apache.jackrabbit.oak.spi.security.authentication.AbstractLoginModule;
import org.apache.jackrabbit.oak.spi.security.authentication.PreAuthenticatedLogin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.jcr.Credentials;
import javax.jcr.SimpleCredentials;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.util.Collections;
import java.util.Set;

public class KeycloakLoginModule extends AbstractLoginModule implements LoginModule {

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakLoginModule.class);

    private static final Set<Class> SUPPORTED_CREDENTIALS = Collections.singleton(KeycloakCredentials.class);

    @Override
    public boolean login() throws LoginException {
        Credentials credentials = getCredentials();
        if (credentials instanceof KeycloakCredentials) {
            KeycloakCredentials keycloakCredentials = (KeycloakCredentials) credentials;
            String userId = keycloakCredentials.getUserId();
            if (userId == null) {
                LOG.warn("Could not extract userId/credentials");
            } else {
                sharedState.put(SHARED_KEY_PRE_AUTH_LOGIN, new PreAuthenticatedLogin(userId));
                sharedState.put(SHARED_KEY_CREDENTIALS, new SimpleCredentials(userId, new char[0]));
                sharedState.put(SHARED_KEY_LOGIN_NAME, userId);
                sharedState.put(KeycloakCredentials.class.getName(), keycloakCredentials);
                LOG.debug("login succeeded with trusted user: {}", userId);
            }
        }
        // subsequent login modules need to succeed and process the 'PreAuthenticatedLogin'
        return false;
    }

    @Override
    public boolean commit() throws LoginException {
        // this module leaves subject population to the subsequent modules
        // that already handled the login with 'PreAuthenticatedLogin' marker.
        return false;
    }

    @Nonnull
    @Override
    protected Set<Class> getSupportedCredentials() {
        return SUPPORTED_CREDENTIALS;
    }
}
