package com.composum.platform.auth.keycloak;

import org.apache.commons.lang3.StringUtils;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.PersistenceException;
import org.apache.sling.auth.core.spi.AuthenticationFeedbackHandler;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.DefaultAuthenticationFeedbackHandler;
import org.apache.sling.jcr.resource.api.JcrResourceConstants;
import org.keycloak.adapters.saml.SamlSession;
import org.keycloak.adapters.saml.SamlSessionStore;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import static com.composum.platform.auth.keycloak.KeycloakAuthenticationFilterPlugin.debug;

/**
 * Authentication handler that uses Keycloak to perform authentication for us, which is handling the the nitty gritty details of login via various providers for us. We use SAML to interface Keycloak, since that seems simpler to include than using OpenID.
 *
 * @see "https://www.keycloak.org/docs-api/4.8/javadocs/index.html"
 */
@Component(name = "Composum Platform Keycloak Authentication Handler",
        property = {
                AuthenticationHandler.TYPE_PROPERTY + "=" + KeycloakAuthenticationHandler.KEYCLOAK_AUTH,
                AuthenticationHandler.PATH_PROPERTY + "=/",
        },
        service = {AuthenticationHandler.class, AuthenticationFeedbackHandler.class},
        immediate = true)
public class KeycloakAuthenticationHandler extends DefaultAuthenticationFeedbackHandler implements AuthenticationHandler {

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakAuthenticationHandler.class);

    public static final String KEYCLOAK_AUTH = "Keycloak";

    /**
     * Session attribute name and attribute name in authinfo. Written by Keycloak's auth library.
     */
    public static final String ATTR_SAMLSESSION = SamlSession.class.getName();

    /**
     * Session attribute where we store a mark that the user user was synchronized with the repository to avoid
     * doing that several times a session.
     */
    protected static final String ATTR_USERISSYNCHRONIZED = KeycloakAuthenticationHandler.class.getName() + "_user";

    private ComponentContext context;

    @Reference
    private KeycloakSynchronizationService keycloakSynchronizationService;

    @Activate
    private void activate(final ComponentContext context) {
        this.context = context;
    }

    public static SamlSession getAccount(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) return null;
        Object sessionAttribute = session.getAttribute(ATTR_SAMLSESSION);
        if (sessionAttribute == null || sessionAttribute instanceof SamlSession) {
            return (SamlSession) sessionAttribute;
        } else {
            LOG.error(ATTR_SAMLSESSION + " not instance of SamlSession. Logout.");
            logout(request, session);
            return null;
        }
    }

    protected static void logout(HttpServletRequest request, HttpSession session) {
        if (session != null) { session.invalidate(); }
        try {
            request.logout();
        } catch (ServletException e) {
            LOG.error("" + e, e);
        }
    }

    @Override
    public AuthenticationInfo extractCredentials(HttpServletRequest request, HttpServletResponse response) {
        LOG.info("extractCredentials {}", request.getRequestURI());
        AuthenticationInfo result = null;
        SamlSession samlSession = getAccount(request);
        if (samlSession != null) {
            LOG.info("Found SamlSession");
            debug("extractCredentials found SamlSession", request, LOG);
            KeycloakCredentials credentials = new KeycloakCredentials(samlSession);
            try {
                if (createOrUpdateUser(credentials, request)) {
                    LOG.info("Credentials created: {}", credentials);
                    result = new AuthenticationInfo(KEYCLOAK_AUTH, credentials.getUserId());
                    result.put(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS, credentials);
                } else {
                    LOG.info("Could get user for {}", credentials.getUserId());
                }
            } catch (RepositoryException | LoginException | PersistenceException e) {
                LOG.error("Trouble creating/getting user " + credentials.getUserId(), e);
            }
        }
        return result;
    }

    /**
     * Calls the {@link KeycloakSynchronizationService#createOrUpdateUser(KeycloakCredentials)} once a session to
     * create or update the user.
     */
    protected boolean createOrUpdateUser(KeycloakCredentials credentials, HttpServletRequest request) throws RepositoryException, LoginException, PersistenceException {
        HttpSession session = request.getSession(false);
        SavedUserMarker savedUserMarker = session != null ? (SavedUserMarker) session.getAttribute(ATTR_USERISSYNCHRONIZED) : null;
        if (savedUserMarker == null) {
            Authorizable authinfo = keycloakSynchronizationService.createOrUpdateUser(credentials);
            if (authinfo != null) {
                savedUserMarker = new SavedUserMarker(authinfo.getID(), session != null ? session.getId() : null);
                if (session != null) { session.setAttribute(ATTR_USERISSYNCHRONIZED, savedUserMarker); }
                LOG.info("Synchronized user {}", credentials.getUserId());
            } else {
                LOG.error("Synchronization service could not find / create user for " + credentials.getUserId());
                return false;
            }
        }
        if (!savedUserMarker.validate(credentials.getUserId(), session)) {
            LOG.error("Inconsistent state - logging out: different user " + credentials.getUserId() + " than saved in" +
                    " session " + savedUserMarker.userid);
            logout(request, session);
            return false;
        }
        return true;
    }

    @Override
    public boolean requestCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {
        LOG.info("requestCredentials {}", request.getRequestURI());
        debug("requestCredentials", request, LOG);
        boolean result = false;
        return result;
    }

    @Override
    public void dropCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {
        LOG.info("dropCredentials {}", request.getRequestURI());
        debug("dropCredentials", request, LOG);
        HttpSession session = request.getSession(false);
        if (null != session) {
            session.removeAttribute(SamlSession.class.getName());
            session.removeAttribute(SamlSessionStore.CURRENT_ACTION);
            session.removeAttribute(ATTR_SAMLSESSION);
            session.removeAttribute(ATTR_USERISSYNCHRONIZED);
            // TODO idmapper?
        }
    }

    /**
     * Serves as a marker in the session that the user was created / updated in the JCR, so that we don't try that
     * again.
     */
    private static class SavedUserMarker {
        protected final String userid;
        protected final String sessionId;

        public SavedUserMarker(String userid, String sessionId) {
            this.userid = userid;
            this.sessionId = sessionId;
        }

        /** "Safety" check that the marker applies to this user and this session. */
        public boolean validate(String userId, HttpSession session) {
            return StringUtils.equals(userId, this.userid) &&
                    StringUtils.equals(sessionId, session != null ? session.getId() : null);
        }
    }

}
