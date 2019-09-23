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

    protected volatile SessionIdTransferConfiguration configuration;

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
        String token = storeService.checkin(finalUrl, configuration.triggerTokenTimeoutMillis());
        URI authUrl = new URI(cfg.authenticationHostUrl());
        URI redirUri = new URI(authUrl.getScheme(), authUrl.getUserInfo(), authUrl.getHost(), authUrl.getPort(),
                SessionIdTransferTriggerServlet.PATH, SessionIdTransferTriggerServlet.PARAM_TOKEN + "=" + token, null);
        return redirUri.toASCIIString();
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

        String sessionIdValue = retrieveSessionIdCookieValue(request);
        String expectedHost = StringUtils.defaultIfBlank(uri.getHost(), request.getServerName());
        String token = registerSessionTransferInfo(new SessionTransferInfo(sessionIdValue, url, expectedHost));

        URI redirURI = new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), SessionIdTransferCallbackServlet.PATH,
                SessionIdTransferCallbackServlet.PARAM_TOKEN + "=" + token,
                null);
        return redirURI.toASCIIString();
    }

    /** The session id in the cookie has a different suffix than the actual session id, so we look it up in the cookie. */
    @Nullable
    protected String retrieveSessionIdCookieValue(@Nonnull HttpServletRequest request) {
        SessionIdTransferConfigurationService.SessionIdTransferConfiguration cfg = getConfiguration();
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

    /** Registers a {@link SessionTransferInfo} and returns the token for which it was registered. */
    @Nonnull
    protected String registerSessionTransferInfo(@Nonnull SessionTransferInfo sessionTransferInfo) {
        String token = storeService.checkin(sessionTransferInfo, configuration.callbackTokenTimeoutMillis());
        LOG.debug("registerTransferInfo with redirect to {}", sessionTransferInfo.url);
        // deliberately *not* log token to prevent intrusion if logfile is accessible
        return token;
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

    // configuration service methods

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
