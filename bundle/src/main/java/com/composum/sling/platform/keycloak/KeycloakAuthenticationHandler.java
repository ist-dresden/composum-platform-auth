package com.composum.sling.platform.keycloak;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.Principal;
import java.util.Collections;

/**
 * Authentication handler that uses Keycloak to perform authentication for us, which is handling the the nitty gritty details of login via various providers for us. We use SAML to interface Keycloak, since that seems simpler to include than using OpenID.
 *
 * @see "https://www.keycloak.org/docs-api/4.8/javadocs/index.html"
 */
@Component(name = "com.composum.sling.platform.keycloak.KeycloakAuthenticationHandler",
        property = {
                AuthenticationHandler.TYPE_PROPERTY + "=" + KeycloakAuthenticationHandler.KEYCLOAK_AUTH,
                AuthenticationHandler.PATH_PROPERTY + "=/content/test/composum/authtest",
        },
        service = {AuthenticationHandler.class, AuthenticationFeedbackHandler.class},
        immediate = true)
public class KeycloakAuthenticationHandler extends DefaultAuthenticationFeedbackHandler implements AuthenticationHandler {

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakAuthenticationHandler.class);

    public static final String KEYCLOAK_AUTH = "Keycloak";

    /**
     * Session attribute name and attribute name in authinfo.
     */
    public static final String ATTR_SAMLSESSION = SamlSession.class.getName();

    private ComponentContext context;

    @Activate
    private void activate(final ComponentContext context) {
        this.context = context;
    }

    public static SamlSession getAccount(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) return null;
        if (session.getAttribute(ATTR_SAMLSESSION) instanceof SamlSession) {
            return (SamlSession) session.getAttribute(ATTR_SAMLSESSION);
        } else {
            LOG.warn(ATTR_SAMLSESSION + " not instance of SamlSession. Logout.");
            session.invalidate();
            try {
                request.logout();
            } catch (ServletException e) {
                LOG.error("" + e, e);
            }
            return null;
        }
    }

    @Override
    public AuthenticationInfo extractCredentials(HttpServletRequest request, HttpServletResponse response) {
        LOG.info("extractCredentials");
        debug(request);
        AuthenticationInfo result = null;
        SamlSession samlSession = getAccount(request);
        if (samlSession != null) {
            result = new AuthenticationInfo(KEYCLOAK_AUTH, samlSession.getPrincipal().getSamlSubject());
            result.put(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS, samlSession);
        }
        return result;
    }

    @Override
    public boolean requestCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {
        LOG.info("requestCredentials");
        debug(request);
        boolean result = false;
        return result;
    }

    @Override
    public void dropCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {
        LOG.info("dropCredentials");
        debug(request);
        HttpSession session = request.getSession(false);
        if (null != session) {
            session.removeAttribute(SamlSession.class.getName());
            session.removeAttribute(SamlSessionStore.CURRENT_ACTION);
            // TODO idmapper?
        }
    }

    private void debug(HttpServletRequest request) {
        try {
            Principal userPrincipal = request.getUserPrincipal();
            if (null != userPrincipal) {
                LOG.info("UserPrincipal: {}", ToStringBuilder.reflectionToString(userPrincipal, ToStringStyle.MULTI_LINE_STYLE, true));
            }
            HttpSession session = request.getSession(false);
            if (session != null) {
                for (String name : Collections.list(session.getAttributeNames())) {
                    LOG.info("Attr {} = {}", name, session.getAttribute(name));
                }
                SamlSession samlSession = getAccount(request);
                LOG.info("SamlSession: {}", ToStringBuilder.reflectionToString(samlSession, ToStringStyle.DEFAULT_STYLE, true));
                LOG.info("Principal: {}", ToStringBuilder.reflectionToString(samlSession.getPrincipal(), ToStringStyle.DEFAULT_STYLE, true));
                LOG.info("Assertion: {}", ToStringBuilder.reflectionToString(samlSession.getPrincipal().getAssertion(), ToStringStyle.DEFAULT_STYLE, true));
            }
        } catch (Exception e) {
            LOG.error(e.toString());
        }
    }
}
