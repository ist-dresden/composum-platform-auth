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

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
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
        try {
            super.doFilter(req, res, chain);
        } catch (Exception e) { // TODO only logout if the error was in the SamlFilter, not in the chain.
            LOG.error("error in doFilter", e);
            HttpSession session = ((HttpServletRequest) req).getSession();
            idMapper.removeSession(session.getId());
            session.invalidate();
            request.logout();
        }
        LOG.info("<< doFilter");
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
                SamlSession samlSession = (SamlSession) session.getAttribute(SamlSession.class.getName());
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
                LOG.info("SamlSession: {}", ToStringBuilder.reflectionToString(samlSession, toStringStyle, true));
            }
        } catch (Exception e) {
            LOG.error("{}", e);
        }
    }

}
