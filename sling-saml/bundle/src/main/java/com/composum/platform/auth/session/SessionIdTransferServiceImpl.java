package com.composum.platform.auth.session;

import com.composum.platform.commons.storage.TokenizedShorttermStoreService;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

/**
 * Implementation of {@link SessionIdTransferService}.
 *
 * @see SessionIdTransferService
 */
@Component(
        service = {SessionIdTransferService.class},
        property = {
                Constants.SERVICE_DESCRIPTION + "=Composum Platform Auth Session Transfer Service"
        },
        configurationPolicy = ConfigurationPolicy.REQUIRE,
        immediate = true
)
@Designate(ocd = SessionIdTransferServiceImpl.Config.class)
public class SessionIdTransferServiceImpl implements SessionIdTransferService {

    private static final Logger LOG = LoggerFactory.getLogger(SessionIdTransferServiceImpl.class);

    @ObjectClassDefinition(name = "Composum Platform Auth SessionId Transfer",
            description = "A servlet filter that provides the ability to transfer the session-id of a user to another" +
                    " virtual host, that is, set the session id cookie there. CAUTION: the cookie configuration must be " +
                    "identical to the configuration in the 'Apache Felix Jetty Based HTTP Service' configuration."
    )
    @interface Config {

        @AttributeDefinition(name = "enabled", description =
                "The on/off switch for the service")
        boolean enabled() default false;

        @AttributeDefinition(name = "Session Cookie name", description =
                "The name of the session cookie (default JSESSIONID).")
        String sessionCookieName() default "JSESSIONID";

        @AttributeDefinition(name = "httpOnly", required = false, description =
                "Session Cookie httpOnly (true by default).")
        boolean httpOnly() default true;

        @AttributeDefinition(name = "Session Domain", required = false, description =
                "If this property is set, then it is used as the domain for session cookies. If it is not set, then no " +
                        "domain is set for the session cookie. Default is none.")
        String sessionDomain() default "";

        @AttributeDefinition(name = "Session Path", required = false, description =
                "If this property is set, then it is used as the path for the session cookie. Default is context path.")
        String sessionPath() default "";

        @AttributeDefinition(name = "Session Cookie secure", required = false, description =
                "Session Cookie secure (false by default).")
        boolean sessionCookieSecure() default false;

        @AttributeDefinition(name = "Authentication host URL", description =
                "Mandatory URL to the host we use as primary authentication host - that is, where the Keycloak " +
                        "(or other) SSO is configured to redirect to after authentication."
        )
        String authenticationHostUrl();

        @AttributeDefinition(name = "Login Timeout", description =
                "The validity time in milliseconds for tokens that transfer the URL the user wants to access to " +
                        "another virtual host, to start transporting the session-id to the current host. " +
                        "This needs to be large enough so that the user can login into the primary authentication " +
                        "host, possibly via Keycloak or different SSO mechanisms.")
        int authenticationTimeoutMillis() default 300000; // 5 minutes time for login

        @AttributeDefinition(name = "Transfer Timeout", description =
                "The validity time in milliseconds for the token that transfers the session to another virtual host." +
                        "This can be relatively small (a few seconds) the user is immediately redirected by the " +
                        "SessionIdTransferTriggerServlet  to the SessionIdTransferCallbackServlet.")
        int transferTimeoutMillis() default 5000;
    }

    protected volatile Config config;

    protected volatile URI authenticationHostUrl;

    @Reference
    protected TokenizedShorttermStoreService storeService;

    @Override
    public boolean usePrimaryAuthenticationHost(@NotNull HttpServletRequest request) {
        URI authUrl = this.authenticationHostUrl;
        if (config == null || !config.enabled() || authUrl == null) {
            return false;
        }
        URI requestUrl;
        try {
            requestUrl = new URI(request.getRequestURL().toString());
        } catch (URISyntaxException e) {
            LOG.error("Impossible: cannot parse request URL " + request.getRequestURL(), e);
            return false;
        }

        boolean onAuthenticationHost = StringUtils.equals(authUrl.getHost(), requestUrl.getHost())
                && authUrl.getPort() == requestUrl.getPort()
                && StringUtils.equals(authUrl.getScheme(), requestUrl.getScheme());
        LOG.debug("should redirect: {} vs {} -> {}", requestUrl, authUrl, onAuthenticationHost);
        return !onAuthenticationHost;
    }

    @Override
    public String initiateSessionTransfer(@NotNull final HttpServletRequest request, @Nullable final String url) {
        String finalUrl = url;
        if (StringUtils.isBlank(url)) {
            final StringBuffer urlBuilder = request.getRequestURL();
            final String queryString = request.getQueryString();
            if (StringUtils.isNotBlank(queryString)) {
                urlBuilder.append('?').append(queryString);
            }
            finalUrl = urlBuilder.toString();
        }
        Map<String, Serializable> payload = new HashMap<>();
        payload.put(PL_CEATION_TIME, System.currentTimeMillis());
        payload.put(PL_FINAL_URL, finalUrl);
        return storeService.checkin(payload, config.authenticationTimeoutMillis());
    }

    @Override
    public void prepreSessionTransfer(@NotNull final HttpServletRequest request, @Nullable final String token) {
        if (config != null && config.enabled() && StringUtils.isNotBlank(token)) {
            final Map<String, Serializable> payload = getPayload(token, false);
            final String finalUrl;
            if (payload != null
                    && (finalUrl = (String) payload.get(PL_FINAL_URL)) != null) {
                try {
                    final URI targetUri = new URI(finalUrl);
                    payload.put(PL_SESSION_ID, retrieveSessionIdCookieValue(request));
                    payload.put(PL_TARGET_HOST, StringUtils.defaultIfBlank(targetUri.getHost(), request.getServerName()));
                    storeService.push(token, payload, config.transferTimeoutMillis());
                    LOG.debug("transfer info stored with redirect to {}", finalUrl);
                } catch (URISyntaxException ex) {
                    LOG.error(ex.toString());
                }
            }
        }
    }

    @Nullable
    @Override
    public String performSessionTransfer(@NotNull final HttpServletRequest request, @Nullable final String token,
                                         @NotNull final HttpServletResponse response) {
        if (config != null && config.enabled() && StringUtils.isNotBlank(token)) {
            final Map<String, Serializable> payload = getPayload(token, true);
            final String targetHost;
            final String sessionId;
            final String finalUrl;
            if (payload != null
                    && (StringUtils.isNotBlank(targetHost = (String) payload.get(PL_TARGET_HOST)))
                    && (StringUtils.isNotBlank(sessionId = (String) payload.get(PL_SESSION_ID)))
                    && (StringUtils.isNotBlank(finalUrl = (String) payload.get(PL_FINAL_URL)))) {
                if (!StringUtils.equals(targetHost, request.getServerName())) {
                    LOG.error("Received session transfer for {} at unexpected host {}", targetHost, request.getServerName());
                    return null;
                }
                HttpSession oldSession = request.getSession(false);
                String oldSessionId = oldSession != null ? oldSession.getId() : null;
                if (oldSessionId != null && StringUtils.indexOfDifference(oldSessionId, sessionId) < 32) {
                    // direct comparison would be wrong since these have a different suffix
                    oldSession.invalidate();
                    LOG.debug("Invalidating old session was necessary - {} for {}", oldSessionId, request.getRequestURL());
                }
                if (sessionId.equals(oldSessionId)) {
                    setSessionCookie(response, sessionId);
                } else {
                    LOG.info("No need to change session id.");
                }
                return finalUrl;
            }
        }
        return null;
    }

    private void setSessionCookie(HttpServletResponse response, String sessionId) {
        Cookie sessionCookie = new Cookie(config.sessionCookieName(), sessionId);
        sessionCookie.setPath(StringUtils.defaultIfBlank(config.sessionPath(), "/"));
        if (StringUtils.isNotBlank(config.sessionDomain())) {
            sessionCookie.setDomain(config.sessionDomain());
        }
        sessionCookie.setHttpOnly(config.httpOnly());
        sessionCookie.setSecure(config.sessionCookieSecure());
        response.addCookie(sessionCookie);
    }

    /**
     * The session id in the cookie has a different suffix than the actual session id, so we look it up in the cookie.
     */
    @Nullable
    protected String retrieveSessionIdCookieValue(@NotNull HttpServletRequest request) {
        if (config == null || !config.enabled()) {
            return null;
        }
        String sessionIdValue = null;
        for (Cookie cookie : request.getCookies()) {
            if (StringUtils.equals(config.sessionCookieName(), cookie.getName())) {
                sessionIdValue = cookie.getValue();
            }
        }

        String sessionId = request.getSession().getId();
        int difference = StringUtils.indexOfDifference(sessionIdValue, sessionId);
        if (difference < 30) { // safety check - weird thing that shouldn't happen.
            LOG.error("Session cookie value is strangely different from session id - not redirecting. {}", difference);
            throw new IllegalStateException("Session cookie value is strangely different from session id - not " +
                    "redirecting. " + difference);
        }

        return sessionIdValue;
    }

    @Nullable
    @SuppressWarnings("unchecked")
    protected Map<String, Serializable> getPayload(@NotNull final String token, boolean close) {
        return close ? storeService.checkout(token, Map.class) : storeService.peek(token, Map.class);
    }

    @Nullable
    @Override
    public String getAuthenticationUrl(@NotNull final HttpServletRequest request, @Nullable final String token,
                                       @NotNull final String uri) {
        if (config != null && config.enabled()) {
            try {
                final URI authUrl = new URI(config.authenticationHostUrl());
                final URI redirUri = new URI(
                        authUrl.getScheme(), null, authUrl.getHost(), authUrl.getPort(),
                        uri, StringUtils.isNotBlank(token) ? (PARAM_TOKEN + "=" + token) : null, null);
                return redirUri.toASCIIString();
            } catch (URISyntaxException ex) {
                LOG.error(ex.toString());
            }
        }
        return null;
    }

    @Override
    @Nullable
    public String getSessionHostUrl(@NotNull final HttpServletRequest request, @Nullable final String token,
                                    @NotNull final String uri) {
        if (config != null && config.enabled()) {
            final Map<String, Serializable> payload;
            final String finalUrl;
            if (StringUtils.isNotBlank(token) && (payload = getPayload(token, false)) != null
                    && (finalUrl = (String) payload.get(PL_FINAL_URL)) != null) {
                try {
                    final URI targetUri = new URI(finalUrl);
                    URI redirURI = new URI(
                            targetUri.getScheme(), null, targetUri.getHost(), targetUri.getPort(),
                            uri, PARAM_TOKEN + "=" + token, null);
                    return redirURI.toASCIIString();
                } catch (URISyntaxException e) {
                    e.printStackTrace();
                }
            }
        }
        return null;
    }

    // configuration service methods

    @Activate
    @Modified
    public void activate(SessionIdTransferServiceImpl.Config configuration) {
        config = configuration;
        authenticationHostUrl = null;
        LOG.info("enabled: {}", config.enabled());
        if (config.enabled()) {
            try {
                authenticationHostUrl = new URI(config.authenticationHostUrl());
            } catch (URISyntaxException e) {
                LOG.error("Parse error for configured authentication URL {} : {}",
                        config.authenticationHostUrl(), e);
            }
        }
    }

    @Deactivate
    public void deactivate() {
        config = null;
        authenticationHostUrl = null;
    }
}
