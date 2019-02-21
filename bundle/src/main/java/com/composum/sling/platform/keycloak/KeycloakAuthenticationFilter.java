package com.composum.sling.platform.keycloak;

import org.apache.commons.lang3.builder.MultilineRecursiveToStringStyle;
import org.apache.commons.lang3.builder.RecursiveToStringStyle;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.apache.felix.scr.annotations.sling.SlingFilter;
import org.apache.felix.scr.annotations.sling.SlingFilterScope;
import org.keycloak.adapters.saml.SamlConfigResolver;
import org.keycloak.adapters.saml.SamlDeploymentContext;
import org.keycloak.adapters.saml.SamlSession;
import org.keycloak.adapters.saml.servlet.SamlFilter;
import org.keycloak.adapters.spi.InMemorySessionIdMapper;
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

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        SamlConfigResolver configResolver = new SlingSamlConfigResolver();
        deploymentContext = new SamlDeploymentContext(configResolver);
        idMapper = new InMemorySessionIdMapper();
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        LOG.info(">> doFilter");
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        debug(request);
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
        LOG.info("<< doFilter");
        debug(request);
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

    static void debug(HttpServletRequest request) {
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
                SamlSession samlSession = KeycloakAuthenticationHandler.getAccount(request);
                LOG.info("SamlSession: {}", ToStringBuilder.reflectionToString(samlSession, ToStringStyle.DEFAULT_STYLE, true));
                LOG.info("Principal: {}", ToStringBuilder.reflectionToString(samlSession.getPrincipal(), ToStringStyle.DEFAULT_STYLE, true));
                LOG.info("Assertion: {}", ToStringBuilder.reflectionToString(samlSession.getPrincipal().getAssertion(), ToStringStyle.DEFAULT_STYLE, true));
            }
        } catch (Exception e) {
            LOG.error(e.toString());
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
                // LOG.info("SamlSession: {}", ToStringBuilder.reflectionToString(samlSession, toStringStyle, true));
            }
        } catch (Exception e) {
            LOG.error("{}", e);
        }
    }

}
