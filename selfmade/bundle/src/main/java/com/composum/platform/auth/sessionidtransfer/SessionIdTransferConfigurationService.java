package com.composum.platform.auth.sessionidtransfer;

import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

import javax.annotation.Nullable;

/** Service for the configuration of the {@link SessionIdTransferCallbackServlet} / {@link SessionIdTransferService}. */
public interface SessionIdTransferConfigurationService {

    /** Retrieves the configuration for the sessionid transfer. */
    @Nullable
    SessionIdTransferConfiguration getConfiguration();

    @ObjectClassDefinition(name = "Composum Platform Auth SessionId Transfer",
            description = "A servlet filter that provides the ability to transfer the session-id of a user to another" +
                    " virtual host, that is, set the session id cookie there. CAUTION: the cookie configuration must be " +
                    "identical to the configuration in the 'Apache Felix Jetty Based HTTP Service' configuration."
    )
    @interface SessionIdTransferConfiguration {

        @AttributeDefinition(name = "enabled", required = true, description =
                "The on/off switch for the filter")
        boolean enabled() default false;

        @AttributeDefinition(name = "Session Cookie name", required = true, description =
                "The name of the session cookie (default JSESSIONID).")
        String sessionCookieName() default "JSESSIONID";

        @AttributeDefinition(name = "httpOnly", required = false, description =
                "Session Cookie httpOnly (true by default).")
        boolean httpOnly() default true;

        @AttributeDefinition(name = "Session Domain", required = false, description =
                "If this property is set, then it is used as the domain for session cookies. If it is not set, then no " +
                        "domain is set for the session cookie. Default is none.")
        String sessionDomain() default "";

        @AttributeDefinition(name = "Session Path", required = false, description =
                "If this property is set, then it is used as the path for the session cookie. Default is context path.")
        String sessionPath() default "";

        @AttributeDefinition(name = "Session Cookie secure", required = false, description =
                "Session Cookie secure (false by default).")
        boolean sessionCookieSecure() default false;

        @AttributeDefinition(name = "Authentication host URL", required = true, description =
                "Mandatory URL to the host we use as primary authentication host - that is, where the Keycloak " +
                        "(or other) SSO is configured to redirect to after authentication."
        )
        String authenticationHostUrl();

        @AttributeDefinition(name = "callbackTokenTimeoutMillis", required = true, description =
                "The validity time in milliseconds for the token that transfers the session to another virtual host." +
                        "This can be relatively small (a few seconds) the user is immediately redirected by the " +
                        "SessionIdTransferTriggerServlet  to the SessionIdTransferCallbackServlet.")
        int callbackTokenTimeoutMillis() default 5000;

        @AttributeDefinition(name = "triggerTokenTimeoutMillis", required = true, description =
                "The validity time in milliseconds for tokens that transfer the URL the user wants to access to " +
                        "another virtual host, to start transporting the session-id to the current host. " +
                        "This needs to be large enough so that the user can login into the primary authentication " +
                        "host, possibly via Keycloak or different SSO mechanisms.")
        int triggerTokenTimeoutMillis() default 300000; // 5 minutes time for login
    }
}
