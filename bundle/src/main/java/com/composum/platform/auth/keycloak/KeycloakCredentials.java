package com.composum.platform.auth.keycloak;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.keycloak.adapters.saml.SamlPrincipal;
import org.keycloak.adapters.saml.SamlSession;

import javax.annotation.Nonnull;
import javax.jcr.Credentials;
import java.util.Objects;

/**
 * Credentials derived from a SAML subject.
 */
public class KeycloakCredentials implements Credentials {

    @Nonnull
    private final SamlSession samlSession;

    public KeycloakCredentials(@Nonnull SamlSession samlSession) {
        this.samlSession = samlSession;
        Objects.requireNonNull(samlSession);
        Objects.requireNonNull(samlSession.getPrincipal());
        Objects.requireNonNull(samlSession.getPrincipal().getSamlSubject());
        if (StringUtils.isBlank(getUserId())) {
            throw new IllegalArgumentException("Blank SamlSubject");
        }
    }

    @Nonnull
    public SamlSession getSamlSession() {
        return samlSession;
    }

    @Nonnull
    public String getUserId() {
        return getSamlSession().getPrincipal().getSamlSubject();
    }

    public String getSurname() {
        return samlSession.getPrincipal().getFriendlyAttribute("surname");
    }

    public String getGivenName() {
        return samlSession.getPrincipal().getFriendlyAttribute("givenName");
    }

    public String getEmail() {
        return samlSession.getPrincipal().getFriendlyAttribute("email");
    }

    /**
     * Something we use as password for the user. That's not a real password - rather a fixed internal id.
     */
    public String getPseudoPassword() {
        return samlSession.getPrincipal().getFriendlyAttribute("nameid");
    }

    @Override
    public String toString() {
        ToStringBuilder builder = new ToStringBuilder(this, ToStringStyle.JSON_STYLE)
                .append("subject", samlSession.getPrincipal().getSamlSubject())
                .append("roles", samlSession.getRoles())
                .append("sessionindex", samlSession.getSessionIndex());
        SamlPrincipal principal = samlSession.getPrincipal();
        if (!principal.getFriendlyNames().isEmpty()) {
            builder.append("friendlyNames", principal.getFriendlyNames());
            for (String name : principal.getFriendlyNames()) {
                builder.append(name, principal.getFriendlyAttributes(name));
            }
        }
        builder.append("attributes", principal.getAttributes());
        // doesn't have sensible output:
        // builder.append("assertion", ToStringBuilder.reflectionToString(principal.getAssertion(), ToStringStyle.JSON_STYLE, true));
        return builder.toString();
    }
}
