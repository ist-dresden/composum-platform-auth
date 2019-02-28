package com.composum.platform.auth.keycloak;

import org.apache.commons.lang3.builder.MultilineRecursiveToStringStyle;
import org.apache.commons.lang3.builder.RecursiveToStringStyle;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.sling.SlingFilter;
import org.apache.felix.scr.annotations.sling.SlingFilterScope;
import org.keycloak.adapters.saml.SamlConfigResolver;
import org.keycloak.adapters.saml.SamlDeploymentContext;
import org.keycloak.adapters.saml.SamlSession;
import org.keycloak.adapters.saml.servlet.SamlFilter;
import org.keycloak.adapters.spi.InMemorySessionIdMapper;
import org.keycloak.saml.common.constants.GeneralConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.Principal;
import java.util.Collection;
import java.util.Collections;

/**
 * Deploys the keycloak {@link SamlFilter} into the Sling environment.
 */
@SlingFilter(
        label = "Composum Platform Authentication Filter",
        description = "a servlet filter to provide authentication with keycloak",
        scope = {SlingFilterScope.REQUEST},
        order = 9000,
        pattern = "/content/test/composum/authtest.*|/saml.*",
        metatype = false)
public class KeycloakAuthenticationFilter extends SamlFilter implements Filter {

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakAuthenticationFilter.class);

    @Reference // TODO why doesn't org.osgi.service.component.annotations.Reference work?
            SamlConfigResolver samlConfigResolver;

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        deploymentContext = new SamlDeploymentContext(samlConfigResolver);
        idMapper = new InMemorySessionIdMapper();
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        if ("true".equals(request.getParameter("logout"))) { // TODO remove when done debugging
            LOG.info("LOGOUT");
            request.logout();
            request.getSession(true).invalidate();
            response.setStatus(HttpServletResponse.SC_OK);
            return;
        }
        LOG.info(">> doFilter");
        debug(">> doFilter", request, LOG);
        if (request.getUserPrincipal() == null || "anonymous".equals(request.getRemoteUser())
                || "true".equals(request.getParameter(GeneralConstants.GLOBAL_LOGOUT))) {
            ExceptionSavingFilterChain chainWrapper = new ExceptionSavingFilterChain(chain);
            try {
                super.doFilter(req, res, chainWrapper);
            } catch (IOException | ServletException | RuntimeException e) {
                if (chainWrapper.exception == null) { // some exception in SamlFilter, not the chain. -> Logout.
                    LOG.error("error in doFilter", e);
                    logout(request);
                }
                throw e;
            }
        } else { // user already logged in - do nothing.
            chain.doFilter(request, response);
        }
        LOG.info("<< doFilter");
        debug("<< doFilter", request, LOG);
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
