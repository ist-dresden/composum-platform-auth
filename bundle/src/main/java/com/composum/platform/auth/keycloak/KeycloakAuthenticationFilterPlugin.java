package com.composum.platform.auth.keycloak;

import com.composum.sling.platform.security.PlatformAccessFilterAuthPlugin;
import org.apache.commons.lang3.builder.MultilineRecursiveToStringStyle;
import org.apache.commons.lang3.builder.RecursiveToStringStyle;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.keycloak.adapters.saml.SamlAuthenticator;
import org.keycloak.adapters.saml.SamlConfigResolver;
import org.keycloak.adapters.saml.SamlDeployment;
import org.keycloak.adapters.saml.SamlDeploymentContext;
import org.keycloak.adapters.saml.SamlSession;
import org.keycloak.adapters.saml.SamlSessionStore;
import org.keycloak.adapters.saml.profile.SamlAuthenticationHandler;
import org.keycloak.adapters.saml.profile.webbrowsersso.BrowserHandler;
import org.keycloak.adapters.saml.profile.webbrowsersso.SamlEndpoint;
import org.keycloak.adapters.saml.servlet.FilterSamlSessionStore;
import org.keycloak.adapters.saml.servlet.SamlFilter;
import org.keycloak.adapters.servlet.ServletHttpFacade;
import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.spi.InMemorySessionIdMapper;
import org.keycloak.adapters.spi.SessionIdMapper;
import org.osgi.framework.Constants;
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
import javax.servlet.FilterChain;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Deploys the keycloak {@link SamlFilter} into the Sling environment.
 */
@Component(
        service = {PlatformAccessFilterAuthPlugin.class},
        property = {
                Constants.SERVICE_DESCRIPTION + "=Composum Platform Keycloak Authentication Plugin"
        }
)
@Designate(ocd = KeycloakAuthenticationFilterPlugin.Config.class)
public final class KeycloakAuthenticationFilterPlugin implements PlatformAccessFilterAuthPlugin {

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakAuthenticationFilterPlugin.class);

    private static final Pattern PROTOCOL_PATTERN = Pattern.compile("^[a-zA-Z][a-zA-Z0-9+.-]*:");

    /**
     * Pattern for the /saml URL that this filter must always cover.
     */
    protected static final Pattern SAMLREQUESTPATTERN = Pattern.compile("/saml.*");

    @Reference
    protected SamlConfigResolver samlConfigResolver;

    protected volatile Config config;
    protected SessionIdMapper idMapper;
    protected SamlDeploymentContext deploymentContext;

    @ObjectClassDefinition(
            name = "Composum Platform Keycloak Plugin Configuration",
            description = "A servlet filter plugin to provide authentication using a Keycloak server"
    )
    @interface Config {
        @AttributeDefinition(
                name = "keycloak.filter.enabled",
                description = "the on/off switch for the filter"
        )
        boolean enabled() default true;
    }

    @Activate
    @Modified
    public final void activate(final Config config) {
        this.config = config;
        idMapper = new InMemorySessionIdMapper();
        deploymentContext = new SamlDeploymentContext(Objects.requireNonNull(samlConfigResolver));
    }

    @Deactivate
    public final void deactivate() {
        deploymentContext = null;
        idMapper = null;
        config = null;
    }

    @Override
    public boolean examineRequest(SlingHttpServletRequest request, SlingHttpServletResponse response,
                                  FilterChain chain)
            throws ServletException, IOException {
        boolean isEndpoint = request.getRequestURI().substring(request.getContextPath().length()).endsWith("/saml");
        if (isEndpoint) {
            ServletHttpFacade facade = new ServletHttpFacade(request, response);
            SamlDeployment deployment = deploymentContext.resolveDeployment(facade);
            FilterSamlSessionStore tokenStore = new FilterSamlSessionStore(request, facade, 100000, idMapper);
            SamlAuthenticator authenticator = new SamlAuthenticator(facade, deployment, tokenStore) {
                @Override
                protected void completeAuthentication(SamlSession account) {

                }

                @Override
                protected SamlAuthenticationHandler createBrowserHandler(HttpFacade facade, SamlDeployment deployment, SamlSessionStore sessionStore) {
                    return new SamlEndpoint(facade, deployment, sessionStore);
                }
            };
            return doAuthenticate(request, response, deployment, facade, tokenStore, authenticator);
        } else if ("true".equals(request.getParameter("logout"))) { // TODO remove when done debugging
            LOG.info("LOGOUT");
            request.logout();
            request.getSession(true).invalidate();
            response.setStatus(HttpServletResponse.SC_OK);
            return true;
        }
        return false;
    }

    @Override
    public boolean triggerAuthentication(SlingHttpServletRequest request, SlingHttpServletResponse response,
                                         FilterChain chain)
            throws ServletException, IOException {
        ServletHttpFacade facade = new ServletHttpFacade(request, response);
        SamlDeployment deployment = deploymentContext.resolveDeployment(facade);
        FilterSamlSessionStore tokenStore = new FilterSamlSessionStore(request, facade, 100000, idMapper);
        SamlAuthenticator authenticator = new SamlAuthenticator(facade, deployment, tokenStore) {
            @Override
            protected void completeAuthentication(SamlSession account) {

            }

            @Override
            protected SamlAuthenticationHandler createBrowserHandler(HttpFacade facade, SamlDeployment deployment, SamlSessionStore sessionStore) {
                return new BrowserHandler(facade, deployment, sessionStore);
            }
        };
        return doAuthenticate(request, response, deployment, facade, tokenStore, authenticator);
    }

    protected boolean doAuthenticate(@Nonnull final SlingHttpServletRequest request,
                                     @Nonnull final SlingHttpServletResponse response,
                                     @Nonnull final SamlDeployment deployment, @Nonnull final ServletHttpFacade facade,
                                     @Nonnull final FilterSamlSessionStore tokenStore,
                                     @Nonnull final SamlAuthenticator authenticator)
            throws ServletException, IOException {
        AuthOutcome outcome = authenticator.authenticate();
        if (outcome == AuthOutcome.AUTHENTICATED) {
            LOG.debug("AUTHENTICATED");
            if (facade.isEnded()) {
                return true;
            }
            return false;
        }
        if (outcome == AuthOutcome.LOGGED_OUT) {
            tokenStore.logoutAccount();
            String logoutPage = deployment.getLogoutPage();
            if (logoutPage != null) {
                if (PROTOCOL_PATTERN.matcher(logoutPage).find()) {
                    response.sendRedirect(logoutPage);
                    LOG.debug("Redirected to logout page '{}'", logoutPage);
                } else {
                    RequestDispatcher dispatcher = request.getRequestDispatcher(logoutPage);
                    if (dispatcher != null) {
                        dispatcher.forward(request, response);
                    } else {
                        LOG.warn("no dispatcher to forward to logout page");
                    }
                }
                return true;
            }
            return false;
        }

        AuthChallenge challenge = authenticator.getChallenge();
        if (challenge != null) {
            LOG.debug("challenge");
            challenge.challenge(facade);
            return true;
        }

        if (deployment.isIsPassive() && outcome == AuthOutcome.NOT_AUTHENTICATED) {
            LOG.debug("PASSIVE_NOT_AUTHENTICATED");
            if (facade.isEnded()) {
                return true;
            }
        }

        if (!facade.isEnded()) {
            response.sendError(403);
            return true;
        }
        return false;
    }

    protected void logout(HttpServletRequest request) throws ServletException {
        HttpSession session = request.getSession(false);
        if (session != null) {
            idMapper.removeSession(session.getId());
            session.invalidate();
        }
        request.logout();
    }

    /**
     * Saves exceptions occuring in the wrapped chain.
     */
    protected static class ExceptionSavingFilterChain implements FilterChain {

        private final FilterChain wrappedChain;

        /**
         * The exception that occured during execution of {@link #doFilter(ServletRequest, ServletResponse)} of wrappedChain.
         */
        protected Exception exception;

        public ExceptionSavingFilterChain(FilterChain wrappedChain) {
            this.wrappedChain = wrappedChain;
        }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
            try {
                wrappedChain.doFilter(request, response);
            } catch (IOException | ServletException | RuntimeException e) {
                this.exception = e;
                throw e;
            }
        }
    }

    static void debug(String calllocation, HttpServletRequest request, Logger log) {
        if (!log.isInfoEnabled()) return;

        StringBuilder buf = new StringBuilder();
        try {
            Principal userPrincipal = request.getUserPrincipal();
            if (null != userPrincipal) {
                buf.append("UserPrincipal: ").append(ToStringBuilder.reflectionToString(userPrincipal, ToStringStyle.MULTI_LINE_STYLE, true));
            }
            HttpSession session = request.getSession(false);
            if (session != null) {
                buf.append("\nSessionID: ").append(session.getId());
                for (String name : Collections.list(session.getAttributeNames())) {
                    buf.append("\nAttr ").append(name).append(" = ").append(session.getAttribute(name));
                }
                SamlSession samlSession = KeycloakAuthenticationHandler.getAccount(request);
                if (null != samlSession) {
                    buf.append("\nSamlSession: ").append(ToStringBuilder.reflectionToString(samlSession, ToStringStyle.DEFAULT_STYLE, true));
                    buf.append("\nPrincipal: ").append(ToStringBuilder.reflectionToString(samlSession.getPrincipal(), ToStringStyle.DEFAULT_STYLE, true));
                    buf.append("\nAssertion: ").append(ToStringBuilder.reflectionToString(samlSession.getPrincipal().getAssertion(), ToStringStyle.DEFAULT_STYLE, true));
                }
            }
        } catch (Exception e) {
            log.error("debug", e);
        }
        try {
            HttpSession session = request.getSession(false);
            if (session != null) {
                SamlSession samlSession = (SamlSession) session.getAttribute(SamlSession.class.getName());
                RecursiveToStringStyle toStringStyle = new MultilineRecursiveToStringStyle() {
                    @Override
                    public void append(final StringBuffer buffer, final String fieldName, final Object value, final Boolean fullDetail) {
                        if (null != value && !(value instanceof Collection && ((Collection) value).isEmpty()))
                            super.append(buffer, fieldName, value, fullDetail);
                    }

                    @Override
                    public void append(final StringBuffer buffer, final String fieldName, final boolean[] array, final Boolean fullDetail) {
                        if (null != array || array.length == 0) super.append(buffer, fieldName, array, fullDetail);
                    }
                };
                if (0 == 1 && samlSession != null) {
                    buf.append("\nSamlSession: ").append(ToStringBuilder.reflectionToString(samlSession, toStringStyle, true));
                }
            }
        } catch (Exception e) {
            log.error("debug", e);
        }
        if (buf.length() > 0) log.info("Session info at {} for {}\n{}", calllocation, request.getRequestURI(), buf);
    }

}
