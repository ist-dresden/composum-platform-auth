package com.composum.platform.auth.keycloak;

import com.composum.sling.platform.security.PlatformAccessFilterAuthPlugin;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.MultilineRecursiveToStringStyle;
import org.apache.commons.lang3.builder.RecursiveToStringStyle;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.keycloak.adapters.saml.SamlConfigResolver;
import org.keycloak.adapters.saml.SamlDeploymentContext;
import org.keycloak.adapters.saml.SamlSession;
import org.keycloak.adapters.saml.servlet.SamlFilter;
import org.keycloak.adapters.spi.InMemorySessionIdMapper;
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
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
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
@Designate(ocd = KeycloakAuthenticationFilter.Config.class)
public class KeycloakAuthenticationFilter extends SamlFilter implements PlatformAccessFilterAuthPlugin {

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakAuthenticationFilter.class);

    /**
     * Pattern for the /saml URL that this filter must always cover.
     */
    protected static final Pattern SAMLREQUESTPATTERN = Pattern.compile("/saml.*");

    @Reference
    protected SamlConfigResolver samlConfigResolver;

    protected volatile Config config;

    @Nonnull
    protected volatile List<Pattern> protectedUrlPatterns = Collections.EMPTY_LIST;

    @ObjectClassDefinition(
            name = "Composum Platform Keycloak Filter Configuration",
            description = "A servlet filter to provide authentication using a Keycloak server"
    )
    @interface Config {
        @AttributeDefinition(
                name = "keycloak.filter.enabled",
                description = "the on/off switch for the filter"
        )
        boolean enabled() default true;

        @AttributeDefinition(
                name = "Protected URIs",
                description = "URI patterns (regex matching the full request.getURI() ) that for which keycloak authentication is tried. " +
                        "You'll probably want to use .* on the end of each pattern."
        )
        String[] protected_uri_patterns() default {
                "/content/test/composum/authtest.*" // FIXME preliminary, for testing purposes
        };
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // this just avoids that SamlFilter.init() is called, which is wrong in a Sling context.
    }

    @Activate
    @Modified
    public final void activate(final Config config) {
        this.config = config;
        idMapper = new InMemorySessionIdMapper();
        deploymentContext = new SamlDeploymentContext(Objects.requireNonNull(samlConfigResolver));
        List<Pattern> patterns = new ArrayList<>();
        patterns.add(SAMLREQUESTPATTERN);
        for (String pattern : config.protected_uri_patterns()) {
            if (StringUtils.isNotBlank(pattern)) patterns.add(Pattern.compile(pattern.trim()));
        }
        protectedUrlPatterns = patterns;
    }

    @Deactivate
    public final void deactivate() {
        this.config = null;
        protectedUrlPatterns = Collections.EMPTY_LIST;
    }

    protected boolean isActiveFor(String requestURI) {
        if (!config.enabled()) return false;
        for (Pattern pattern : protectedUrlPatterns) {
            if (pattern.matcher(requestURI).matches()) return true;
        }
        return false;
    }

    @Override
    public boolean examineRequest(SlingHttpServletRequest request, SlingHttpServletResponse response,
                                  FilterChain chain)
            throws ServletException {
        if ("true".equals(request.getParameter("logout"))) { // TODO remove when done debugging
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
        ExceptionSavingFilterChain chainWrapper = new ExceptionSavingFilterChain(chain);
        try {
            super.doFilter(request, response, chainWrapper);
        } catch (IOException | ServletException e) {
            if (chainWrapper.exception == null) { // some exception in SamlFilter, not the chain. -> Logout.
                LOG.error("error in doFilter", e);
                logout(request);
            }
            throw e;
        }
        return true;
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
