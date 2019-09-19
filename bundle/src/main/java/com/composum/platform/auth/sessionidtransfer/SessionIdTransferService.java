package com.composum.platform.auth.sessionidtransfer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Service implementing functionality wrt. the {@link SessionIdTransferFilter}: transfer the session-id cookie to
 * different virtual hosts running on the same instance.
 *
 * @see SessionIdTransferFilter
 */
public interface SessionIdTransferService {

    /** A parameter that contains the token for transferring the session id. */
    String PARAM_SESSIONIDTOKEN = "sessionIdTransferToken";


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
        final long tokenCreationTime;

        private TransferInfo(@Nonnull String sessionId, @Nonnull String url) {
            this.sessionId = sessionId;
            this.url = url;
            this.tokenCreationTime = System.currentTimeMillis();
        }
    }
}
