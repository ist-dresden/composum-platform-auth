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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URISyntaxException;

/**
 * Part 1 of two servlets to transfer a session from the primary authentication host (possibly triggering a login) to
 * another virtual host. The path {@value #PATH} of this servlet should be configured to trigger a login. The servlet
 * accepts a parameter {@value PARAM_TOKEN} with a token created by
 * {@link SessionIdTransferService#sessionTransferTriggerUrl(String, HttpServletRequest)} for which the final URL is
 * stored. The task of this servlet is to possibly trigger a login of the user (being a protected URL) and then do a
 * callback to the {@link SessionIdTransferCallbackServlet} on the host for the final URL that transfers the current
 * session cookie there.
 * <p>
 * The need for this mechanism arises since since Keycloak always needs a manual declaration of hosts it can redirect
 * to in the case of logins, and we need an automatically changeable dynamic number of virtual hosts (e.g. preview
 * hosts) where the user has to
 * log in, this provides a possibility to transfer the users session to a different host.
 *
 * @see SessionIdTransferCallbackServlet
 */
@Component(service = Servlet.class,
        property = {
                Constants.SERVICE_DESCRIPTION + "=Composum Platform Auth Session ID Transfer Trigger Servlet",
                ServletResolverConstants.SLING_SERVLET_PATHS + "=" + SessionIdTransferTriggerServlet.PATH,
                ServletResolverConstants.SLING_SERVLET_METHODS + "=" + HttpConstants.METHOD_GET
        },
        immediate = true
)
public class SessionIdTransferTriggerServlet extends SlingSafeMethodsServlet {

    private static final Logger LOG = LoggerFactory.getLogger(SessionIdTransferTriggerServlet.class);

    /**
     * Parameter with a token under which to retrieve the
     * {@link SessionIdTransferService.SessionTransferInfo}
     */
    public static final String PARAM_TOKEN = "urlToken";

    /** Deployment path of this {@link SessionIdTransferTriggerServlet}. */
    public static final String PATH = "/bin/cpm/platform/auth/sessionTransferTrigger";

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
            String finalUrl = transferService.retrieveFinalUrl(token);
            if (finalUrl != null) {
                String redirectUrl = null;
                try {
                    redirectUrl = transferService.sessionTransferCallbackUrl(finalUrl, request);
                } catch (URISyntaxException e) { // should be impossible
                    LOG.error("Something is broken about " + finalUrl + " or " + cfg.authenticationHostUrl(), e);
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Internal error");
                }
                if (StringUtils.isNotBlank(redirectUrl)) {
                    LOG.info("Redirecting to callback servlet for {}", finalUrl);
                    response.sendRedirect(redirectUrl);
                }
            } else { // invalid token or timed out. Nothing sensible we can do here...
                LOG.warn("Could not retrieve transferinfo for token {}", token);
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Session transfer token timed out or invalid.");
            }
        }
    }

}
