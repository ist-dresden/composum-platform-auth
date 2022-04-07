package com.composum.platform.auth.session;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Service to transfer the session-id cookie to different virtual hosts running on the same instance.
 */
public interface SessionIdTransferService {

    String PARAM_TOKEN = "token";

    String PL_FINAL_URL = "finalUrl";
    String PL_FORM_AUTH = "formAuth";
    String PL_SESSION_ID = "sessionId";
    String PL_TARGET_HOST = "targetHost";
    String PL_CEATION_TIME = "ceationTime";

    /**
     * Checks whether we are at the primary authentication host, as configured in
     * {@link SessionIdTransferService.Config#authenticationHostUrl()}, or
     * should redirect there via {@link #getAuthenticationUrl()} for authentication.
     *
     * @return true if the requests host is the
     * {@link SessionIdTransferService.Config#authenticationHostUrl()} and
     * {@link SessionIdTransferService.Config#enabled()},
     * otherwise false.
     */
    boolean isPrimaryAuthHost(@NotNull HttpServletRequest request);

    /**
     * Initializes the transfer processing - creates a token for data synchronization between sessions.
     *
     * @param request  the current request on the final (virtual) host
     * @param finalUrl the optional final URL after synchronization (default: the current URL of the request)
     * @return the created token
     */
    String initiateSessionTransfer(@NotNull HttpServletRequest request, @Nullable String finalUrl);

    /**
     * Provides the data of the authenticated session on the authentication host for transfer to the final host.
     *
     * @param request the current request on the authentocation host
     * @param token   the token to use for transfer
     */
    void prepreSessionTransfer(@NotNull HttpServletRequest request, @Nullable String token);

    /**
     * Copies the authenticated session to the final host
     *
     * @param request  the current request on the authentocation host
     * @param token    the token to use for transfer
     * @param response the current response for cookie management
     * @return the final URL; the final redirect target
     */
    @Nullable
    String performSessionTransfer(@NotNull HttpServletRequest request, @Nullable String token,
                                  @NotNull HttpServletResponse response);

    /**
     * Returns the final URL assigend to the given token
     *
     * @param token the session transfer token
     * @param close if 'true' the associated transfer is aborted
     * @return the final URL if such an URL can be retrieved, otherwise 'null'
     */
    @Nullable
    String getFinalUrl(@Nullable String token, boolean close);

    /**
     * Returns a URL to the primary authentication host.
     *
     * @param token the session transfer token to use
     * @param uri   the authentication host target URI
     * @return the redirection URL or null if the service is not enabled.
     */
    @Nullable
    String getAuthenticationUrl(@NotNull HttpServletRequest request, @Nullable String token, @NotNull String uri);

    /**
     * Returns a URL on the {url}s host.
     * This requires that that host is another virtual host accessing the same server as ourselves.
     *
     * @return the redirection URL or null if the service is not enabled.
     */
    @Nullable
    String getSessionHostUrl(@NotNull HttpServletRequest request, @Nullable String token, @NotNull String uri);
}
