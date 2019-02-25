package com.composum.platform.auth.keycloak;

import org.apache.felix.jaas.LoginModuleFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

import javax.security.auth.spi.LoginModule;

/**
 * Creates KeycloakLoginModules.
 */
@Component(service = LoginModuleFactory.class, immediate = true)
@Designate(ocd = KeycloakLoginModuleFactory.Configuration.class)
public class KeycloakLoginModuleFactory implements LoginModuleFactory {

    private Configuration config;

    @ObjectClassDefinition(name = "Keycloak Login Module Factory",
            description = "Factory for Keycloak Login Modules")
    protected @interface Configuration {

        @AttributeDefinition(name = "JAAS Ranking", description = "Specifying the ranking (i.e. sort order) of this " +
                "login module entry. The entries are sorted in a descending order (i.e. higher value ranked configurations come first).")
        int jaas_ranking() default 500;

        @AttributeDefinition(name = "JAAS Control Flag", description =
                "Property specifying whether or not a LoginModule is REQUIRED, REQUISITE, SUFFICIENT or " +
                        "OPTIONAL. Refer to the JAAS configuration documentation for more details around the meaning of " +
                        "these flags.")
        String jaas_controlFlag() default "SUFFICIENT";

        @AttributeDefinition(name = "JAAS Realm", description =
                "The realm name (or application name) against which the LoginModule  is be registered. If no " +
                        "realm name is provided then LoginModule is registered with a default realm as configured in " +
                        "the Felix JAAS configuration.")
        String jaas_realmName();

    }

    @Activate
    @Modified
    protected final void activate(final ComponentContext componentContext, final Configuration config) {
        this.config = config;
    }

    @Deactivate
    protected final void deactivate(final ComponentContext componentContext) {
        config = null;
    }


    @Override
    public LoginModule createLoginModule() {
        return new KeycloakLoginModule();
    }

}
