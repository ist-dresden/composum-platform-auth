package com.composum.platform.auth.plugin;

import com.composum.platform.auth.session.SessionIdTransferService;
import com.composum.sling.core.util.ValueEmbeddingWriter;
import com.composum.sling.platform.security.PlatformAccessFilterAuthPlugin;
import org.apache.commons.lang3.StringUtils;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
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

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import static com.composum.platform.auth.session.SessionIdTransferService.PARAM_TOKEN;

/**
 * The PlatformAccessFilterAuthPlugin implementation to support the authentication on a virtual host
 * via the systems primary host. If an authentication is triggered on a virtual host a token is created and stored
 * in the session on the vhost. The token id is sent to the primary host and stored in its coresponding session too.
 */
@Component(
        service = {PlatformAccessFilterAuthPlugin.class},
        property = {
                Constants.SERVICE_DESCRIPTION + "=Composum Platform Access Filter Plugin SAML"
        },
        configurationPolicy = ConfigurationPolicy.REQUIRE,
        immediate = true
)
@Designate(ocd = SamlAccessFilterAuthPlugin.Config.class)
public final class SamlAccessFilterAuthPlugin implements PlatformAccessFilterAuthPlugin {

    private static final Logger LOG = LoggerFactory.getLogger(SamlAccessFilterAuthPlugin.class);

    public static final String SA_TOKEN = SamlAccessFilterAuthPlugin.class.getSimpleName() + "#token";

    @ObjectClassDefinition(
            name = "Composum Platform Access Filter Plugin SAML",
            description = "A platform access filter plugin to provide authentication redirect for various hosts."
    )
    @interface Config {

        @AttributeDefinition(
                name = "Enabled",
                description = "the on/off switch for the filter"
        )
        boolean enabled() default false;

        @AttributeDefinition(
                name = "Prepare URI",
                description = "the URI to prepare session transfer (URI to primary host for session sync)"
        )
        String prepareUri() default "/bin/public/auth/session/prepare";

        @AttributeDefinition(
                name = "Login URI",
                description = "the URI to trigger the authentication (secured URI on primary host)"
        )
        String triggerUri() default "/bin/private/auth/session";

        @AttributeDefinition(
                name = "Transfer URI",
                description = "the URI to perform the session transfer to the designated host/domain"
        )
        String transferUri() default "/bin/public/auth/session/transfer";

        @AttributeDefinition(
                name = "Local SAML Endpoint",
                description = "the optional URI of the local SAML authentication callback; if present a 'breaking through' request is blocked by the access filter"
        )
        String samlCallbackUri() default "/bin/public/auth/saml";

        @AttributeDefinition(
                name = "Blocked Redirect",
                description = "the optional target URL to redirect a blocked request; default: ${scheme}://${host}:${port}${context}"
        )
        String redirectBlocked() default "${scheme}://${host}:${port}${context}";
    }

    @Reference
    private SessionIdTransferService sessionIdTransferService;

    private Config config;

    @Activate
    @Modified
    public void activate(final Config config) {
        this.config = config;
    }

    @Deactivate
    public void deactivate() {
        config = null;
    }

    @Override
    public boolean triggerAuthentication(SlingHttpServletRequest request, SlingHttpServletResponse response,
                                         FilterChain chain)
            throws IOException {
        if (config.enabled() && !sessionIdTransferService.isPrimaryAuthHost(request)) {
            final HttpSession session = request.getSession(true);
            final String token = sessionIdTransferService.initiateSessionTransfer(request, null);
            session.setAttribute(SA_TOKEN, token);
            final String redirUrl = sessionIdTransferService.getAuthenticationUrl(request, token, config.prepareUri());
            redirect(request, response, redirUrl, "trigger");
            return true;
        }
        return false;
    }

    @Override
    public boolean examineRequest(SlingHttpServletRequest request, SlingHttpServletResponse response,
                                  FilterChain chain)
            throws IOException {
        if (config.enabled()) {
            final String host = request.getServerName();
            final String path = request.getResource().getPath();
            if (config.prepareUri().equals(path)) {
                LOG.debug("[{}].prepare: redirect for authentication...", host);
                prepareAuthentication(request, response);
                return true;
            } else if (config.triggerUri().equals(path)) {
                LOG.debug("[{}].trigger: redirect to requested host...", host);
                redirectSession(request, response);
                return true;
            } else if (config.transferUri().equals(path)) {
                LOG.debug("[{}].transfer: build host related session...", host);
                transferSession(request, response);
                return true;
            } else if (config.samlCallbackUri().equals(path)) {
                LOG.debug("[{}].block: breaking through SAML request", host);
                blockRequest(request, response);
                return true;
            }
        }
        return false;
    }

    @Nullable
    private String retrieveToken(@NotNull final SlingHttpServletRequest request,
                                 @Nullable final SlingHttpServletResponse response,
                                 @NotNull final String step)
            throws IOException {
        String token = request.getParameter(PARAM_TOKEN);
        if (StringUtils.isBlank(token)) {
            final HttpSession session = request.getSession(false);
            if (session != null) {
                token = (String) session.getAttribute(SA_TOKEN);
            }
        }
        if (StringUtils.isBlank(token) && response != null) {
            final String host = request.getServerName();
            LOG.error("[{}].{}: Token missing.", host, step);
            blockRequest(request, response);
        }
        return token;
    }

    /**
     * executed on the primary authentication host to synchronize the 'token' session attribute
     */
    private void prepareAuthentication(@NotNull final SlingHttpServletRequest request,
                                       @NotNull final SlingHttpServletResponse response)
            throws IOException {
        final String token = request.getParameter(PARAM_TOKEN);
        final HttpSession session = request.getSession(true);
        if (StringUtils.isNotBlank(token)) {
            session.setAttribute(SA_TOKEN, token);
            final String redirUrl = sessionIdTransferService.getAuthenticationUrl(request, token, config.triggerUri());
            redirect(request, response, redirUrl, "prepare");
        } else {
            final String host = request.getServerName();
            session.removeAttribute(SA_TOKEN);
            LOG.error("[{}].prepare: Token missing.", host);
            blockRequest(request, response);
        }
    }

    /**
     * executed on the primary authentication host to redirect to the final host for session transfer
     */
    private void redirectSession(@NotNull final SlingHttpServletRequest request,
                                 @NotNull final SlingHttpServletResponse response)
            throws IOException {
        final String token = retrieveToken(request, response, "redirect");
        if (StringUtils.isNotBlank(token)) {
            sessionIdTransferService.prepreSessionTransfer(request, token);
            final String redirUrl = sessionIdTransferService.getSessionHostUrl(request, token, config.transferUri());
            redirect(request, response, redirUrl, "redirect");
        }
    }

    /**
     * executed on the final host to finalize the session transfer
     */
    private void transferSession(@NotNull final SlingHttpServletRequest request,
                                 @NotNull final SlingHttpServletResponse response)
            throws IOException {
        final String token = retrieveToken(request, response, "transfer");
        if (StringUtils.isNotBlank(token)) {
            final String finalUrl = sessionIdTransferService.performSessionTransfer(request, token, response);
            redirect(request, response, finalUrl, "transfer");
        }
    }

    /**
     * executed on aborting the session transfer or on blocking an unexpected SAML callback
     */
    private void blockRequest(@NotNull final SlingHttpServletRequest request,
                              @NotNull final SlingHttpServletResponse response)
            throws IOException {
        String redirectUrl = null;
        final String token = retrieveToken(request, null, "block");
        if (StringUtils.isNotBlank(token)) {
            redirectUrl = sessionIdTransferService.getFinalUrl(token, true);
        }
        if (StringUtils.isBlank(redirectUrl)) {
            redirectUrl = config.redirectBlocked();
            if (StringUtils.isNotBlank(redirectUrl)) {
                redirectUrl = redirectUrl(request, redirectUrl);
            }
        }
        if (StringUtils.isNotBlank(redirectUrl)) {
            response.sendRedirect(redirectUrl);
        } else {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
        }
    }

    private void redirect(@NotNull final SlingHttpServletRequest request,
                          @NotNull final SlingHttpServletResponse response,
                          @Nullable final String redirectUrl, @NotNull final String step)
            throws IOException {
        final String host = request.getServerName();
        if (StringUtils.isNotBlank(redirectUrl)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("[{}].redirecting to {}", host, redirectUrl.replaceFirst("\\?.*", ""));
            }
            response.sendRedirect(redirectUrl);
        } else {
            LOG.error("[{}].{}: session transfer not possible ({})", host, step, request.getRequestURL());
            blockRequest(request, response);
        }
    }

    @NotNull
    private String redirectUrl(@NotNull final SlingHttpServletRequest request, @NotNull String redirectUrl) {
        Map<String, Object> values = new HashMap<>();
        values.put("scheme", request.getScheme());
        values.put("host", request.getServerName());
        values.put("port", request.getServerPort());
        values.put("context", request.getContextPath());
        values.put("uri", request.getRequestURI());
        values.put("path", request.getResource().getPath());
        values.put("query", request.getQueryString());
        return redirectUrl(redirectUrl, values);
    }

    @NotNull
    private String redirectUrl(@NotNull String redirectUrl, @NotNull final Map<String, Object> values) {
        try (StringWriter urlWriter = new StringWriter();
             ValueEmbeddingWriter embeddingWriter = new ValueEmbeddingWriter(urlWriter, values)) {
            embeddingWriter.append(redirectUrl);
            redirectUrl = urlWriter.toString();
        } catch (IOException ex) {
            LOG.error(ex.getMessage(), ex);
        }
        return redirectUrl;
    }
}
