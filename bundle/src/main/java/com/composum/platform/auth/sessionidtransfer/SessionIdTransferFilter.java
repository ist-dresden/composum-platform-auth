package com.composum.platform.auth.sessionidtransfer;

import org.apache.commons.lang3.StringUtils;
import org.osgi.framework.Constants;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.metatype.annotations.Designate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * Restores the session-id from a redirect from a different virtual host accessing the same sling instance.
 * Since Keycloak always needs a manual declaration of hosts it can redirect to in the case of logins
 * and we need an automatically changeable dynamic number of virtual hosts (e.g. preview hosts) where the user has to
 * log in, this provides a possibility to transfer the users session to a different host.
 */
@Component(
        service = {Filter.class, SessionIdTransferConfigurationService.class},
        property = {
                "sling.filter.scope=REQUEST",
                Constants.SERVICE_DESCRIPTION + "=Composum Platform Auth SessionId Transfer",
                Constants.SERVICE_RANKING + ":Integer=9",
        },
        configurationPolicy = ConfigurationPolicy.REQUIRE
)
@Designate(ocd = SessionIdTransferConfigurationService.SessionIdTransferConfiguration.class)
public class SessionIdTransferFilter implements Filter, SessionIdTransferConfigurationService {

    private static final Logger LOG = LoggerFactory.getLogger(SessionIdTransferFilter.class);

    @Reference
    SessionIdTransferService sessionIdTransferService;

    protected volatile SessionIdTransferConfigurationService.SessionIdTransferConfiguration configuration;
    protected ServletContext filterConfig;
    protected ComponentContext context;

    @Override
    public void doFilter(ServletRequest rawRequest, ServletResponse rawResponse, FilterChain chain) throws IOException, ServletException {
        SessionIdTransferConfiguration cfg = this.configuration;
        HttpServletRequest request = (HttpServletRequest) rawRequest;
        HttpServletResponse response = (HttpServletResponse) rawResponse;
        String token = request.getParameter(SessionIdTransferService.PARAM_SESSIONIDTOKEN);
        if (cfg != null && cfg.enabled() && StringUtils.isNotBlank(token)) {
            SessionIdTransferService.TransferInfo transferinfo = sessionIdTransferService.retrieveTransferInfo(token);
            if (transferinfo != null) {

                LOG.info("Redirecting to {}", transferinfo.url);
                HttpSession oldSession = request.getSession(false);
                String oldSessionId = oldSession != null ? oldSession.getId() : null;
                if (oldSessionId != null && !oldSessionId.equals(transferinfo.sessionId)) {
                    LOG.info("Invalidating old session");
                    oldSession.invalidate();
                }
                if (!transferinfo.sessionId.equals(oldSessionId)) {
                    setSessionCookie(response, transferinfo.sessionId);
                }
                response.sendRedirect(transferinfo.url);

            } else { // invalid token or timed out. Nothing sensible we can do here...
                LOG.warn("Could not retrieve transferinfo for token {}", token);
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Session transfer token timed out or invalid.");
            }
        } else {
            chain.doFilter(rawRequest, rawResponse);
        }
    }

    protected void setSessionCookie(HttpServletResponse response, String sessionId) {
        LOG.info("Setting new session cookie");
        SessionIdTransferConfiguration cfg = this.configuration;
        Cookie sessionCookie = new Cookie(cfg.sessionCookieName(), sessionId);
        if (StringUtils.isNotBlank(cfg.sessionPath())) { sessionCookie.setPath(cfg.sessionPath()); }
        if (StringUtils.isNotBlank(cfg.sessionDomain())) { sessionCookie.setDomain(cfg.sessionDomain());}
        response.addCookie(sessionCookie);
        
        // FIXME(hps,19.09.19) remove - for testing purposes only.
        Cookie otherCookie = new Cookie("JSESSIONID-NEW", sessionId);
        otherCookie.setMaxAge(-300);
        response.addCookie(otherCookie);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // empty
    }

    @Override
    public void destroy() {
        // empty
    }

    @Activate
    @Modified
    public void activate(SessionIdTransferConfigurationService.SessionIdTransferConfiguration configuration) {
        this.configuration = configuration;
        LOG.info("enabled: " + configuration.enabled());
    }

    @Deactivate
    public void deactivate() {
        configuration = null;
    }

    @Nullable
    @Override
    public SessionIdTransferConfiguration getConfiguration() {
        return configuration;
    }
}
