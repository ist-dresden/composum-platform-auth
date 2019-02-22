package com.composum.sling.platform.keycloak;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.PersistenceException;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import java.security.Principal;
import java.util.Locale;

/**
 * Default implementation of {@link KeycloakSynchronizationService}.
 */
@Component(service = KeycloakSynchronizationService.class, immediate = true)
@Designate(ocd = KeycloakSynchronizationServiceImpl.Configuration.class)
public class KeycloakSynchronizationServiceImpl implements KeycloakSynchronizationService {

    public static final String PLATFORM_SERVICE_USER = "composum-platform-service";

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakSynchronizationServiceImpl.class);

    private Configuration config;

    @Reference
    protected ResourceResolverFactory resolverFactory;

    @ObjectClassDefinition(name = "Keycloak Synchronization Service",
            description = "Creates / updates users authorized by Keycloak")
    protected @interface Configuration {

        @AttributeDefinition(name = "User path", description = "JCR path below which the users are created")
        String userpath() default "/home/users/keycloak";
    }

    @Activate
    @Modified
    protected final void activate(final ComponentContext componentContext, final Configuration config) {
        this.config = config;
    }

    @Deactivate
    protected final void deactivate(final ComponentContext componentContext) {
        config = null;
    }


    @Override
    public Authorizable createOrUpdateUser(@Nonnull KeycloakCredentials credentials) throws RepositoryException, LoginException, PersistenceException {
        // try (ResourceResolver adminResolver = resolverFactory.getServiceResourceResolver(null)) { // FIXME How to do this?
        try (ResourceResolver adminResolver = resolverFactory.getAdministrativeResourceResolver(null)) {
            JackrabbitSession session = (JackrabbitSession) adminResolver.adaptTo(Session.class);
            UserManager userManager = session.getUserManager();
            String userId = credentials.getUserId();
            Authorizable user = userManager.getAuthorizable(userId);
            if (user == null) {
                Principal principal = credentials.getSamlSession().getPrincipal();
                String userpath = config.userpath();
                if (userId.contains("@"))
                    userpath = userpath + "/" + userId.substring(userId.indexOf("@") + 1).toLowerCase(Locale.ROOT);
                user = userManager.createUser(userId, credentials.getPseudoPassword(), principal, userpath);
                Group group = (Group) userManager.getAuthorizable("composum-platform-users");
                group.addMember(user);
                adminResolver.commit();
                LOG.info("User created: {}", user);
            } else {
                LOG.info("User exists for {}", userId);
                // TODO
            }
            return user;
        }
    }
}
