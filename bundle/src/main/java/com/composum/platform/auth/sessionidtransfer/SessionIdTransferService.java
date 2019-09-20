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

    /** A parameter that contains the token for transferring the session id. */
    String PARAM_SESSIONIDTOKEN = "sessionIdTransferToken";

    /**
     * Returns a URL to redirect to that activates the session id transfer and will in the end display the given url
     * in the browser with the current session. Of course, this works only if the url belongs to another virtual host
     * working on this very Sling server, and only works if redirected right now since it'll otherwise timeout.
     *
     * @return the redirection URL or null if the service is not enabled.
     */
    @Nullable
    String redirectUrl(@Nonnull String url, @Nonnull HttpServletRequest request) throws URISyntaxException;

    /** Registers a {@link TransferInfo} and returns the token for which it was registered. */
    @Nonnull
    String registerTransferInfo(@Nonnull TransferInfo transferInfo);

    /**
     * Retrieves the {@link TransferInfo} which was registered at this token - if there was something registered at
     * this token and it hasn't timed out yet.
     */
    @Nullable
    TransferInfo retrieveTransferInfo(@Nullable String token);

    /** The information about one session transfer. */
    class TransferInfo {
        @Nonnull
        final String sessionId;
        @Nonnull
        final String url;
        @Nonnull
        final String expectedHost;
        final long tokenCreationTime;

        public TransferInfo(@Nonnull String sessionId, @Nonnull String url, @Nonnull String expectedHost) {
            this.sessionId = sessionId;
            this.url = url;
            this.expectedHost = expectedHost;
            this.tokenCreationTime = System.currentTimeMillis();
        }
    }
}
