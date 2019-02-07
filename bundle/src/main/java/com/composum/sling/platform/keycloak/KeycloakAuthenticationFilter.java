package com.composum.sling.platform.keycloak;

import org.apache.felix.scr.annotations.sling.SlingFilter;
import org.apache.felix.scr.annotations.sling.SlingFilterScope;
import org.keycloak.adapters.saml.SamlConfigResolver;
import org.keycloak.adapters.saml.SamlDeploymentContext;
import org.keycloak.adapters.saml.servlet.SamlFilter;
import org.keycloak.adapters.spi.InMemorySessionIdMapper;

import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;

@SlingFilter(
        label = "Composum Platform Authentication Filter",
        description = "a servlet filter to provide authentication with keycloak",
        scope = {SlingFilterScope.REQUEST},
        order = 9000,
        pattern = "/content/ist/restricted.*|/saml.*",
        metatype = false)
public class KeycloakAuthenticationFilter extends SamlFilter implements Filter {

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        SamlConfigResolver configResolver = new SlingSamlConfigResolver();
        deploymentContext = new SamlDeploymentContext(configResolver);
        idMapper = new InMemorySessionIdMapper();
    }

}
