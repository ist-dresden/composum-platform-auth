package com.composum.platform.auth.sessionidtransfer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import java.net.URISyntaxException;

/**
 * Service implementing functionality wrt. the {@link SessionIdTransferFilter}: transfer the session-id cookie to
 * different virtual hosts running on the same instance.
 *
 * @see SessionIdTransferFilter
 */
public interface SessionIdTransferService {

    /**
     * Returns a URL on the primary authentication host
     * ( {@link SessionIdTransferConfigurationService.SessionIdTransferConfiguration#authenticationHostUrl()} )  to the
     * {@link SessionIdTransferCallbackServlet} that will in the end redirect the users browser to the given {url} but
     * display it with the session on the authentication host. This requires that the current host is another virtual
     * host accessing the same server as the authentication host (which uses Keycloak or other SSO etc.
     * authentication mechanism).
     *
     * @param url the URL the browser should be redirected to in the end; if null we take the current {request}s URL.
     * @return the redirection URL or null if the service is not enabled.
     */
    @Nullable
    String sessionTransferTriggerUrl(@Nullable String url, @Nonnull HttpServletRequest request) throws URISyntaxException;

    /**
     * Returns the URL registered by {@link #sessionTransferTriggerUrl(String, HttpServletRequest)}.
     *
     * @return the URL or null if the service is notenabled, the token is invalid or timed out
     */
    @Nullable
    String retrieveFinalUrl(@Nullable String token);

    /**
     * Returns a URL on the {url}s host to the {@link SessionIdTransferCallbackServlet},
     * which will set the current session's session-ID there and then
     * and then will redirect to the given url in the browser with the current session.
     * This requires that that host is another virtual host accessing the same server as ourselves.
     *
     * @return the redirection URL or null if the service is not enabled.
     */
    @Nullable
    String sessionTransferCallbackUrl(@Nonnull String url, @Nonnull HttpServletRequest request) throws URISyntaxException;

    /**
     * Retrieves the {@link SessionTransferInfo} which was registered at this token by {@link #sessionTransferCallbackUrl(String, HttpServletRequest)}
     * - if there was something registered at this token and it hasn't timed out yet.
     */
    @Nullable
    SessionTransferInfo retrieveSessionTransferInfo(@Nullable String token);

    /** The information about one session transfer. */
    class SessionTransferInfo {
        @Nonnull
        final String sessionId;
        @Nonnull
        final String url;
        @Nonnull
        final String expectedHost;
        final long tokenCreationTime;

        public SessionTransferInfo(@Nonnull String sessionId, @Nonnull String url, @Nonnull String expectedHost) {
            this.sessionId = sessionId;
            this.url = url;
            this.expectedHost = expectedHost;
            this.tokenCreationTime = System.currentTimeMillis();
        }
    }

}
