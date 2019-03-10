package com.composum.platform.auth.keycloak;

import org.apache.commons.lang3.StringUtils;
import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.PersistenceException;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.jcr.ItemNotFoundException;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.Value;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Default implementation of {@link KeycloakSynchronizationService}.
 */
@Component(service = KeycloakSynchronizationService.class, immediate = true)
@Designate(ocd = KeycloakSynchronizationServiceImpl.Configuration.class)
public class KeycloakSynchronizationServiceImpl implements KeycloakSynchronizationService {

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakSynchronizationServiceImpl.class);

    public static final String PROPERTY_LASTLOGIN = "lastLogin";

    private Configuration config;

    @Reference
    protected ResourceResolverFactory resolverFactory;

    @ObjectClassDefinition(name = "Composum Platform Keycloak Synchronization Service",
            description = "Creates / updates users authorized by Keycloak")
    protected @interface Configuration {

        @AttributeDefinition(name = "User path", description = "JCR path below which the users are created (relative path below /home/users/)")
        String userpath() default "keycloak";

        @AttributeDefinition(name = "New user groups", description = "A set of groups a newly synchronized user is assigned to")
        String[] groups() default {"composum-platform-auth-external"};
    }

    @Activate
    @Modified
    protected final void activate(final ComponentContext componentContext, final Configuration config) throws NoSuchAlgorithmException {
        this.config = config;
    }

    @Deactivate
    protected final void deactivate(final ComponentContext componentContext) {
        config = null;
    }


    @Override
    public Authorizable createOrUpdateUser(@Nonnull KeycloakCredentials credentials) throws RepositoryException, LoginException, PersistenceException {
        try (ResourceResolver serviceResolver = resolverFactory.getServiceResourceResolver(null)) {
            JackrabbitSession session = (JackrabbitSession) serviceResolver.adaptTo(Session.class);
            if (session != null) {
                UserManager userManager = Objects.requireNonNull(session.getUserManager());
                String userId = credentials.getUserId();
                Authorizable user = userManager.getAuthorizable(userId);
                if (user == null) {
                    Principal principal = credentials.getSamlSession().getPrincipal();
                    String userpath = config.userpath();
                    if (userId.contains("@")) {
                        final String domain = userId.substring(userId.indexOf('@') + 1).toLowerCase(Locale.ROOT);
                        final List<String> segments = Arrays.asList(StringUtils.split(domain, "."));
                        Collections.reverse(segments);
                        userpath = userpath + "/" + StringUtils.join(segments, "/");
                    }
                    String pseudoPassword = credentials.getPseudoPassword();
                    if (StringUtils.isBlank(pseudoPassword) || pseudoPassword.length() < 10) {
                        pseudoPassword = null;
                    }
                    user = userManager.createUser(userId, pseudoPassword, principal, userpath);
                    for (String groupname : config.groups()) {
                        Group group = (Group) userManager.getAuthorizable(groupname);
                        if (group != null) {
                            group.addMember(user);
                        } else {
                            LOG.error("Configured default group {} not available", groupname);
                            throw new ItemNotFoundException("Group not found: " + groupname);
                        }
                    }
                    LOG.info("Creating user: {}", userId);
                } else {
                    LOG.info("User exists for {}", userId);
                }
                Value now = session.getValueFactory().createValue(Calendar.getInstance());
                user.setProperty(PROPERTY_LASTLOGIN, now);
                serviceResolver.commit();
                return user;
            } else {
                LOG.error("Can't adatapt service resolver to session!");
                return null;
            }
        }
    }
}
