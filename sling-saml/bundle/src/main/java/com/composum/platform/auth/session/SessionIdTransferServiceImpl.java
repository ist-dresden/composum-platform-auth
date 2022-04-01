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

        @AttributeDefinition(name = "Form Auth Cookie name", description =
                "The name of the Sling form authentication cookie (default sling.formauth).")
        String formAuthCookieName() default "sling.formauth";

        @AttributeDefinition(name = "httpOnly", required = false, description =
                "Session Cookie httpOnly (true by default).")
        boolean httpOnly() default true;

        @AttributeDefinition(name = "Session Domain", required = false, description =
                "If this property is set, then it is used as the domain for cookies. If it is not set, then no " +
                        "domain is set for the cookies. Default is none.")
        String sessionDomain() default "";

        @AttributeDefinition(name = "Session Path", required = false, description =
                "If this property is set, then it is used as the path for the cookies. Default is context path.")
        String sessionPath() default "";

        @AttributeDefinition(name = "Authentication Host URL", description =
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

    private Config config;
    private boolean enabled;
    private URI authHostURI;

    @Reference
    protected TokenizedShorttermStoreService storeService;

    @Override
    public boolean isPrimaryAuthHost(@NotNull HttpServletRequest request) {
        boolean primaryAuthHost = false;
        if (enabled) {
            final String host = request.getServerName();
            primaryAuthHost = StringUtils.equals(authHostURI.getHost(), host);
            LOG.debug("[{}]:isPrimaryAuthenticationHost: {}", host, primaryAuthHost);
        }
        return primaryAuthHost;
    }

    @Override
    public String initiateSessionTransfer(@NotNull final HttpServletRequest request, @Nullable final String url) {
        if (enabled) {
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
        return null;
    }

    @Override
    public void prepreSessionTransfer(@NotNull final HttpServletRequest request, @Nullable final String token) {
        if (enabled && StringUtils.isNotBlank(token)) {
            final Map<String, Serializable> payload = getPayload(token, false);
            final String finalUrl;
            if (payload != null
                    && (finalUrl = (String) payload.get(PL_FINAL_URL)) != null) {
                final String host = request.getServerName();
                try {
                    final URI targetUri = new URI(finalUrl);
                    storeAuthenticationInfo(request, payload);
                    payload.put(PL_TARGET_HOST, StringUtils.defaultIfBlank(targetUri.getHost(), request.getServerName()));
                    storeService.push(token, payload, config.transferTimeoutMillis());
                    LOG.debug("[{}]: transfer info {} stored with redirect to '{}'", host, payload, finalUrl);
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
        if (enabled && StringUtils.isNotBlank(token)) {
            final Map<String, Serializable> payload = getPayload(token, true);
            final String targetHost;
            final String sessionId;
            final String finalUrl;
            if (payload != null
                    && (StringUtils.isNotBlank(targetHost = (String) payload.get(PL_TARGET_HOST)))
                    && (StringUtils.isNotBlank(sessionId = (String) payload.get(PL_SESSION_ID)))
                    && (StringUtils.isNotBlank(finalUrl = (String) payload.get(PL_FINAL_URL)))) {
                final String host = request.getServerName();
                if (!StringUtils.equals(targetHost, request.getServerName())) {
                    LOG.error("[{}]: received session transfer for '{}' at unexpected host", host, targetHost);
                    return null;
                }
                HttpSession oldSession = request.getSession(false);
                String oldSessionId = oldSession != null ? oldSession.getId() : null;
                if (oldSessionId != null && StringUtils.indexOfDifference(oldSessionId, sessionId) < 32) {
                    // direct comparison would be wrong since these have a different suffix
                    oldSession.invalidate();
                    LOG.debug("[{}]: invalidating old session was necessary - '{}' for '{}'",
                            host, oldSessionId, request.getRequestURL());
                }
                final String formAuth = (String) payload.get(PL_FORM_AUTH);
                LOG.debug("[{}]: set cookies [{},{}]", host, sessionId, formAuth);
                setCookie(response, config.sessionCookieName(), sessionId, false);
                if (StringUtils.isNotBlank(formAuth)) {
                    setCookie(response, config.formAuthCookieName(), formAuth, true);
                }
                return finalUrl;
            }
        }
        return null;
    }

    @Nullable
    public String getFinalUrl(@Nullable final String token, boolean close) {
        if (enabled && StringUtils.isNotBlank(token)) {
            final Map<String, Serializable> paylod = getPayload(token, close);
            if (paylod != null) {
                return (String) paylod.get(PL_FINAL_URL);
            }
        }
        return null;
    }

    @Nullable
    @SuppressWarnings("unchecked")
    protected Map<String, Serializable> getPayload(@NotNull final String token, boolean close) {
        return close ? storeService.checkout(token, Map.class) : storeService.peek(token, Map.class);
    }

    /**
     * store session and authentication form cookie values in the payload.
     */
    protected void storeAuthenticationInfo(@NotNull HttpServletRequest request,
                                           @NotNull final Map<String, Serializable> payload) {
        if (enabled) {
            for (Cookie cookie : request.getCookies()) {
                if (StringUtils.equals(config.sessionCookieName(), cookie.getName())) {
                    payload.put(PL_SESSION_ID, cookie.getValue());
                } else if (StringUtils.equals(config.formAuthCookieName(), cookie.getName())) {
                    payload.put(PL_FORM_AUTH, cookie.getValue());
                }
            }
        }
    }

    private void setCookie(@NotNull final HttpServletResponse response,
                           @NotNull final String name, @NotNull final String value, boolean secure) {
        Cookie sessionCookie = new Cookie(name, value);
        sessionCookie.setPath(StringUtils.defaultIfBlank(config.sessionPath(), "/"));
        if (StringUtils.isNotBlank(config.sessionDomain())) {
            sessionCookie.setDomain(config.sessionDomain());
        }
        sessionCookie.setHttpOnly(config.httpOnly());
        sessionCookie.setSecure(secure);
        response.addCookie(sessionCookie);
    }

    @Nullable
    @Override
    public String getAuthenticationUrl(@NotNull final HttpServletRequest request, @Nullable final String token,
                                       @NotNull final String uri) {
        if (enabled) {
            try {
                final URI redirUri = new URI(
                        authHostURI.getScheme(), null, authHostURI.getHost(), authHostURI.getPort(),
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
        if (enabled) {
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
        authHostURI = null;
        if (config.enabled()) {
            try {
                authHostURI = new URI(config.authenticationHostUrl());
            } catch (URISyntaxException e) {
                LOG.error("Parse error for configured authentication URL {} : {}",
                        config.authenticationHostUrl(), e);
            }
        }
        enabled = config != null && config.enabled() && authHostURI != null;
        LOG.info("enabled: {}", enabled);
    }

    @Deactivate
    public void deactivate() {
        enabled = false;
        authHostURI = null;
        config = null;
    }
}
