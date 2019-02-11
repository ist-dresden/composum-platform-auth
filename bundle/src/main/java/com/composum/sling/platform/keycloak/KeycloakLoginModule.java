package com.composum.sling.platform.keycloak;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.util.Map;

public class KeycloakLoginModule implements LoginModule {

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakLoginModule.class);

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        LOG.error("KeycloakLoginModule.initialize");
        // FIXME hps 2019-02-11 implement KeycloakLoginModule.initialize
    }

    @Override
    public boolean login() throws LoginException {
        LOG.error("KeycloakLoginModule.login");
        // FIXME hps 2019-02-11 implement KeycloakLoginModule.login
        boolean result = false;
        return result;
    }

    @Override
    public boolean commit() throws LoginException {
        LOG.error("KeycloakLoginModule.commit");
        // FIXME hps 2019-02-11 implement KeycloakLoginModule.commit
        boolean result = false;
        return result;
    }

    @Override
    public boolean abort() throws LoginException {
        LOG.error("KeycloakLoginModule.abort");
        // FIXME hps 2019-02-11 implement KeycloakLoginModule.abort
        boolean result = false;
        return result;
    }

    @Override
    public boolean logout() throws LoginException {
        LOG.error("KeycloakLoginModule.logout");
        // FIXME hps 2019-02-11 implement KeycloakLoginModule.logout
        boolean result = false;
        return result;
    }
}
