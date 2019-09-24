package com.composum.platform.auth.sessionidtransfer;

import com.composum.platform.commons.storage.TokenizedShorttermStoreService;
import org.apache.commons.lang3.StringUtils;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.metatype.annotations.Designate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;

import static java.util.Objects.requireNonNull;

/**
 * Implementation of {@link SessionIdTransferService}.
 *
 * @see SessionIdTransferService
 */
@Component(
        service = {SessionIdTransferService.class, SessionIdTransferConfigurationService.class},
        property = {
                Constants.SERVICE_DESCRIPTION + "=Composum Platform Auth Session Transfer Service"
        },
        immediate = true
)
@Designate(ocd = SessionIdTransferConfigurationService.SessionIdTransferConfiguration.class)
public class SessionIdTransferServiceImpl implements SessionIdTransferService, SessionIdTransferConfigurationService {

    private static final Logger LOG = LoggerFactory.getLogger(SessionIdTransferServiceImpl.class);

    @Nullable
    protected volatile SessionIdTransferConfiguration configuration;
    @Nullable
    protected volatile URI authenticationHostUrl;

    @Reference
    protected TokenizedShorttermStoreService storeService;


    @Nullable
    @Override
    public String sessionTransferTriggerUrl(@Nullable String url, @Nonnull HttpServletRequest request) throws URISyntaxException {
        SessionIdTransferConfiguration cfg = getConfiguration();
        if (cfg == null || !cfg.enabled()) { return null; }
        String finalUrl = url;
        if (StringUtils.isBlank(url)) {
            StringBuffer buf = request.getRequestURL();
            if (StringUtils.isNotBlank(request.getQueryString())) {
                buf.append('?').append(request.getQueryString());
            }
            finalUrl = buf.toString();
        }
        String token = storeService.checkin(finalUrl, cfg.triggerTokenTimeoutMillis());
        URI authUrl = new URI(cfg.authenticationHostUrl());
        URI redirUri = new URI(authUrl.getScheme(), authUrl.getUserInfo(), authUrl.getHost(), authUrl.getPort(),
                SessionIdTransferTriggerServlet.PATH, SessionIdTransferTriggerServlet.PARAM_TOKEN + "=" + token, null);
        return redirUri.toASCIIString();
    }

    @Nullable
    @Override
    public String sessionTransferTriggerUrl(@Nonnull HttpServletRequest request) {
        try {
            return sessionTransferTriggerUrl(null, request);
        } catch (URISyntaxException e) {
            LOG.error("Impossible - cannot parse current requests URL??? " + e, e);
            throw new IllegalArgumentException(e);
        }
    }

    @Nullable
    @Override
    public String retrieveFinalUrl(@Nullable String token) {
        String url = null;
        SessionIdTransferConfiguration cfg = getConfiguration();
        if (cfg == null || !cfg.enabled()) { return null; }
        if (StringUtils.isNotBlank(token)) {
            url = storeService.checkout(token, String.class);
        }
        return url;
    }

    @Override
    @Nullable
    public String sessionTransferCallbackUrl(@Nonnull String url, @Nonnull HttpServletRequest request) throws URISyntaxException {
        SessionIdTransferConfiguration cfg = getConfiguration();
        if (cfg == null || !cfg.enabled()) { return null; }
        URI uri = new URI(url);

        String sessionIdValue = requireNonNull(retrieveSessionIdCookieValue(request));
        String expectedHost = StringUtils.defaultIfBlank(uri.getHost(), request.getServerName());
        SessionTransferInfo sessionTransferInfo = new SessionTransferInfo(sessionIdValue, url, expectedHost);
        String token = storeService.checkin(sessionTransferInfo, cfg.callbackTokenTimeoutMillis());
        LOG.debug("registerTransferInfo with redirect to {}", sessionTransferInfo.url);
        // deliberately *not* log token to prevent intrusion if logfile is accessible

        URI redirURI = new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), SessionIdTransferCallbackServlet.PATH,
                SessionIdTransferCallbackServlet.PARAM_TOKEN + "=" + token,
                null);
        return redirURI.toASCIIString();
    }

    /** The session id in the cookie has a different suffix than the actual session id, so we look it up in the cookie. */
    @Nullable
    protected String retrieveSessionIdCookieValue(@Nonnull HttpServletRequest request) {
        SessionIdTransferConfigurationService.SessionIdTransferConfiguration cfg = getConfiguration();
        if (cfg == null || !cfg.enabled()) { return null; }
        String sessionIdValue = null;
        for (Cookie cookie : request.getCookies()) {
            if (StringUtils.equals(cfg.sessionCookieName(), cookie.getName())) {
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
    @Override
    public SessionTransferInfo retrieveSessionTransferInfo(@Nullable String token) {
        SessionTransferInfo sessionTransferInfo = null;
        if (StringUtils.isNotBlank(token)) {
            sessionTransferInfo = storeService.checkout(token, SessionTransferInfo.class);
            if (sessionTransferInfo != null) {
                LOG.info("Found transferinfo for token, redirect to {}", sessionTransferInfo.url);
            }
        }
        return sessionTransferInfo;
    }

    @Override
    public boolean authenticationShouldRedirectToPrimaryAuthenticationHost(@Nonnull HttpServletRequest request) {
        SessionIdTransferConfigurationService.SessionIdTransferConfiguration cfg = getConfiguration();
        URI authUrl = this.authenticationHostUrl;
        if (cfg == null || !cfg.enabled() || authUrl == null) { return false; }
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

    // configuration service methods

    @Activate
    @Modified
    public void activate(SessionIdTransferConfigurationService.SessionIdTransferConfiguration theConfiguration) throws URISyntaxException {
        this.configuration = theConfiguration;
        this.authenticationHostUrl = null;
        LOG.info("enabled: {}", theConfiguration.enabled());
        this.authenticationHostUrl = new URI(theConfiguration.authenticationHostUrl());
    }

    @Deactivate
    public void deactivate() {
        configuration = null;
        authenticationHostUrl = null;
    }

    @Nullable
    @Override
    public SessionIdTransferConfiguration getConfiguration() {
        return configuration;
    }
}
