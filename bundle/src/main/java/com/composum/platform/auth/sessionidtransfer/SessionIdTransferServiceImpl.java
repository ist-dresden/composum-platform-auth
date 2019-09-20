package com.composum.platform.auth.sessionidtransfer;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedDeque;

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
        immediate = true
)
public class SessionIdTransferServiceImpl implements SessionIdTransferService {

    private static final Logger LOG = LoggerFactory.getLogger(SessionIdTransferServiceImpl.class);

    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    protected volatile SessionIdTransferConfigurationService configurationService;

    /** Maps tokens to {@link com.composum.platform.auth.sessionidtransfer.SessionIdTransferService.TransferInfo}. */
    protected final Map<String, TransferInfo> transferInfoMap = Collections.synchronizedMap(new HashMap<>());

    /** Queue for tokens in the order of their creation time - for cleanup. */
    protected final Deque<String> tokenToDeleteQueue = new ConcurrentLinkedDeque<>();

    protected final SecureRandom tokenGenerator = new SecureRandom();

    @Override
    @Nullable
    public String redirectUrl(@Nonnull String url, @Nonnull HttpServletRequest request) throws URISyntaxException {
        URI uri = new URI(url);

        String sessionIdValue = retrieveSessionIdCookieValue(request);
        String expectedHost = StringUtils.defaultIfBlank(uri.getHost(), request.getServerName());
        String token = registerTransferInfo(new TransferInfo(sessionIdValue, url, expectedHost));

        URI redirURI = new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), "/", PARAM_SESSIONIDTOKEN + "=" + token,
                null);
        return redirURI.toASCIIString();
    }

    /** The session id in the cookie has a different suffix than the actual session id, so we look it up in the cookie. */
    @Nullable
    protected String retrieveSessionIdCookieValue(@Nonnull HttpServletRequest request) {
        SessionIdTransferConfigurationService.SessionIdTransferConfiguration cfg = configurationService.getConfiguration();
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

    @Nonnull
    @Override
    public String registerTransferInfo(@Nonnull TransferInfo transferInfo) {
        String token = RandomStringUtils.random(32, 0, 0, true, true, null, tokenGenerator);
        cleanup();
        tokenToDeleteQueue.addLast(token);
        transferInfoMap.put(token, transferInfo);
        LOG.debug("registerTransferInfo with redirect to {}", transferInfo.url);
        // deliberately *not* log token to prevent intrusion if logfile is accessible
        return token;
    }

    protected long getMinCreateTime() {
        SessionIdTransferConfigurationService cserv = configurationService;
        SessionIdTransferConfigurationService.SessionIdTransferConfiguration cfg = configurationService != null ? configurationService.getConfiguration() : null;
        long timeout = cfg != null ? cfg.tokenTimeoutMillis() : 5000;
        return System.currentTimeMillis() - timeout;
    }

    protected void cleanup() {
        synchronized (tokenToDeleteQueue) {
            long minCreationTime = getMinCreateTime();
            String token;
            TransferInfo transferInfo;
            token = tokenToDeleteQueue.peekFirst();
            transferInfo = token != null ? transferInfoMap.get(token) : null;
            do {
                token = tokenToDeleteQueue.pollFirst();
                if (token == null) { return; }
                transferInfo = token != null ? transferInfoMap.get(token) : null;
                if (transferInfo != null) {
                    if (transferInfo.tokenCreationTime > minCreationTime) {
                        tokenToDeleteQueue.addFirst(token); // put it back since first one isn't timed out yet, stop.
                        return;
                    } else { // timed out
                        transferInfoMap.remove(token);
                    }
                }
            } while (!tokenToDeleteQueue.isEmpty());
        }
    }

    @Nullable
    @Override
    public TransferInfo retrieveTransferInfo(@Nullable String token) {
        TransferInfo transferInfo = null;
        if (StringUtils.isNotBlank(token)) {
            transferInfo = transferInfoMap.get(token);
            if (transferInfo != null) {
                transferInfoMap.remove(token);
                // tokenToDeleteQueue is automatically cleaned after a while.
                if (transferInfo.tokenCreationTime < getMinCreateTime()) {
                    transferInfo = null;
                    LOG.info("TransferInfo timed out - discarding it.");
                } else {
                    LOG.info("Found transferinfo for token, redirect to {}", transferInfo.url);
                }
            }
        }
        cleanup();
        return transferInfo;
    }
}
