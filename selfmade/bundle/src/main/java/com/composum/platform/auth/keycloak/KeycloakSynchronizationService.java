package com.composum.platform.auth.keycloak;

import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.PersistenceException;

import javax.annotation.Nonnull;
import javax.jcr.RepositoryException;

/**
 * Service that handles the synchronization between keycloak users and local users.
 */
public interface KeycloakSynchronizationService {

    /**
     * Creates or updates a user according to the SAML information contained in the credentials.
     *
     * @param credentials
     */
    Authorizable createOrUpdateUser(@Nonnull KeycloakCredentials credentials) throws RepositoryException, LoginException, PersistenceException;

}
