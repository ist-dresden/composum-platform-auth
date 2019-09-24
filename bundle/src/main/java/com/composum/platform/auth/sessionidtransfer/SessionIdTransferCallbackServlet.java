package com.composum.platform.auth.sessionidtransfer;

import org.apache.commons.lang3.StringUtils;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.HttpConstants;
import org.apache.sling.api.servlets.ServletResolverConstants;
import org.apache.sling.api.servlets.SlingSafeMethodsServlet;
import org.jetbrains.annotations.NotNull;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * Part 2 of two servlets to transfer a session to another virtual nhst.
 * Servlet that receives a redirect from {@link SessionIdTransferTriggerServlet} with a token to retrieve the stored
 * session-ID and the URL to redirect to, which the user originally wanted to access.
 * This servlet must be accessible anonymously (path {@value #PATH}), since it is going to attach the users browser
 * to an existing session.
 *
 * @see SessionIdTransferTriggerServlet
 */
@Component(service = Servlet.class,
        property = {
                Constants.SERVICE_DESCRIPTION + "=Composum Platform Auth Session ID Transfer Callback Servlet",
                ServletResolverConstants.SLING_SERVLET_PATHS + "=" + SessionIdTransferCallbackServlet.PATH,
                ServletResolverConstants.SLING_SERVLET_METHODS + "=" + HttpConstants.METHOD_GET
        },
        immediate = true
)
public class SessionIdTransferCallbackServlet extends SlingSafeMethodsServlet {

    /**
     * Parameter with a token under which to retrieve the
     * {@link SessionIdTransferService.SessionTransferInfo}
     */
    public static final String PARAM_TOKEN = "sessionToken";

    /** Deployment path of this {@link SessionIdTransferCallbackServlet}. */
    public static final String PATH = "/bin/cpm/platform/auth/sessionTransferCallback";

    private static final Logger LOG = LoggerFactory.getLogger(SessionIdTransferCallbackServlet.class);

    @Reference
    protected SessionIdTransferConfigurationService configurationService;

    @Reference
    protected SessionIdTransferService transferService;

    @Override
    protected void doGet(@NotNull SlingHttpServletRequest request, @NotNull SlingHttpServletResponse response) throws ServletException, IOException {
        SessionIdTransferConfigurationService.SessionIdTransferConfiguration cfg = configurationService.getConfiguration();
        String token = request.getParameter(PARAM_TOKEN);
        if (cfg == null || !cfg.enabled()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Session transfer not enabled.");
        } else if (StringUtils.isBlank(token)) {
            LOG.warn("Token parameter missing.");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Token parameter is missing.");
        } else {
            SessionIdTransferService.SessionTransferInfo transferinfo = transferService.retrieveSessionTransferInfo(token);
            if (transferinfo != null) {

                if (!StringUtils.equals(transferinfo.expectedHost, request.getServerName())) {
                    LOG.error("Received session transfer for {} at unexpected host {}", transferinfo.expectedHost, request.getServerName());
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                            "Received session transfer for " + transferinfo.expectedHost + " at " + request.getServerName());
                    return;
                }

                LOG.info("Redirecting to {}", transferinfo.url);
                HttpSession oldSession = request.getSession(false);
                String oldSessionId = oldSession != null ? oldSession.getId() : null;
                if (oldSessionId != null && StringUtils.indexOfDifference(oldSessionId, transferinfo.sessionId) < 32) {
                    // direct comparison would be wrong since these have a different suffix
                    oldSession.invalidate();
                    LOG.info("Invalidating old session was necessary - {}", oldSessionId);
                }
                if (!transferinfo.sessionId.equals(oldSessionId)) {
                    setSessionCookie(response, transferinfo.sessionId);
                } else {
                    LOG.info("No need to change session id.");
                }
                response.sendRedirect(transferinfo.url);

            } else { // invalid token or timed out. Nothing sensible we can do here...
                LOG.warn("Could not retrieve transferinfo for token {}", token);
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Session transfer token timed out or invalid.");
            }
        }
    }

    protected void setSessionCookie(HttpServletResponse response, String sessionId) {
        SessionIdTransferConfigurationService.SessionIdTransferConfiguration cfg = configurationService.getConfiguration();
        Cookie sessionCookie = new Cookie(cfg.sessionCookieName(), sessionId);
        sessionCookie.setPath(StringUtils.defaultIfBlank(cfg.sessionPath(), "/"));
        if (StringUtils.isNotBlank(cfg.sessionDomain())) { sessionCookie.setDomain(cfg.sessionDomain());}
        sessionCookie.setHttpOnly(cfg.httpOnly());
        sessionCookie.setSecure(cfg.sessionCookieSecure());
        response.addCookie(sessionCookie);
    }

}
