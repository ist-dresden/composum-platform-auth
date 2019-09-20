package com.composum.platform.auth.sessionidtransfer;

import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

import javax.annotation.Nullable;

/** Service for the configuration of the {@link SessionIdTransferServlet} / {@link SessionIdTransferService}. */
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

        @AttributeDefinition(name = "enabled", description =
                "The on/off switch for the filter")
        boolean enabled() default false;

        @AttributeDefinition(name = "Session Cookie name", description =
                "The name of the session cookie.")
        String sessionCookieName() default "JSESSIONID";

        @AttributeDefinition(name = "httpOnly", description =
                "Session Cookie httpOnly (true by default).")
        boolean httpOnly() default true;

        @AttributeDefinition(name = "Session Domain", description =
                "If this property is set, then it is used as the domain for session cookies. If it is not set, then no " +
                        "domain is set for the session cookie. Default is none.")
        String sessionDomain() default "";

        @AttributeDefinition(name = "Session Path", description =
                "If this property is set, then it is used as the path for the session cookie. Default is context path.")
        String sessionPath() default "";

        @AttributeDefinition(name = "Session Cookie secure", description =
                "Session Cookie secure (false by default).")
        boolean sessionCookieSecure() default false;

        @AttributeDefinition(name = "tokenTimeout", description =
                "The validity time in milliseconds for tokens that transfer the session to another virtual host.")
        int tokenTimeoutMillis() default 300000;
        // FIXME(hps,19.09.19) change default value to 5000 (seconds)

    }
}
