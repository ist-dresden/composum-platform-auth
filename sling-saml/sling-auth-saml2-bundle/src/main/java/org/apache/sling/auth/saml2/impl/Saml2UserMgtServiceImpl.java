/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sling.auth.saml2.impl;

import org.apache.commons.lang3.StringUtils;
import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.auth.saml2.Saml2User;
import org.apache.sling.auth.saml2.Saml2UserMgtService;
import org.apache.sling.auth.saml2.Saml2UserMgtServiceConfig;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.metatype.annotations.Designate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.ValueFactory;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component(
        service = {Saml2UserMgtService.class}
)
@Designate(ocd = Saml2UserMgtServiceConfig.class, factory = true)
public class Saml2UserMgtServiceImpl implements Saml2UserMgtService {

    private static final Logger LOG = LoggerFactory.getLogger(Saml2UserMgtServiceImpl.class);

    public static final String SERVICE_NAME = "Saml2UserMgtService";

    public static final String USERS_ROOT = "/home/users/";
    public static final Pattern DOMAIN = Pattern.compile("\\{(?<concat>.)?domain(?<join>.)?}");
    public static final Pattern MAIL_ADDR = Pattern.compile("^[^@]+@(?<domain>[^@]+)$");

    @Reference
    private ResourceResolverFactory resolverFactory;

    private Saml2UserMgtServiceConfig config;
    private ComponentContext componentContext;
    private Map<String, String> syncGroupMap;
    private Map<String, String> syncAttrMap;

    @Activate
    @Modified
    protected void activate(final Saml2UserMgtServiceConfig config, ComponentContext componentContext) {
        this.config = config;
        this.componentContext = componentContext;
        this.syncGroupMap = buildKeyMap(config.syncGroups());
        this.syncAttrMap = buildKeyMap(config.syncAttrs());
    }

    @Deactivate
    protected void deactivate() {
        this.componentContext = null;
        this.config = null;
    }

    // prepare / collect

    public void applySaml2Attributes(@Nonnull final Assertion assertion, @Nonnull final Saml2User samlUser) {
        for (Attribute attribute : assertion.getAttributeStatements().get(0).getAttributes()) {
            applyUserId(attribute, samlUser);
            applyGroupMembership(attribute, samlUser);
            applyUserProperty(attribute, samlUser);
        }
    }

    protected void applyUserId(Attribute attribute, Saml2User saml2User) {
        if (attribute.getName().equals(config.saml2userIDAttr())) {
            for (XMLObject attributeValue : attribute.getAttributeValues()) {
                final String value = ((XSString) attributeValue).getValue();
                if (StringUtils.isNotBlank(value)) {
                    saml2User.setId(value);
                    LOG.debug("username value: {}", saml2User.getId());
                }
            }
        }
    }

    protected void applyGroupMembership(@Nonnull final Attribute attribute, @Nonnull final Saml2User saml2User) {
        if (attribute.getName().equals(config.saml2groupMembershipAttr())) {
            for (final XMLObject attributeValue : attribute.getAttributeValues()) {
                final String groupKey = ((XSString) attributeValue).getValue();
                if (StringUtils.isNotBlank(groupKey)) {
                    final String groupId = syncGroupMap.get(groupKey);
                    if (StringUtils.isNotBlank(groupId)) {
                        saml2User.addGroupMembership(groupId);
                        LOG.debug("group '{}' added: '{}'", groupKey, groupId);
                    } else {
                        LOG.debug("group '{}' ignored", groupKey);
                    }
                }
            }
        }
    }

    protected void applyUserProperty(Attribute attribute, Saml2User saml2User) {
        final String propertyName = syncAttrMap.get(attribute.getName());
        if (StringUtils.isNotBlank(propertyName)) {
            for (final XMLObject attributeValue : attribute.getAttributeValues()) {
                final String value = ((XSString) attributeValue).getValue();
                if (value != null) {
                    saml2User.addUserProperty(propertyName, attributeValue);
                    LOG.debug("sync attr '{}': '{}' = '{}'", attribute.getName(), propertyName, value);
                }
            }
        }
    }

    // perform

    public User performUserSynchronization(@Nonnull final Saml2User samlUser) {
        User user = null;
        final String userId = samlUser.getId();
        if (StringUtils.isNotBlank(userId)) {
            try (final ResourceResolver resolver = resolverFactory.getServiceResourceResolver(
                    Collections.singletonMap(ResourceResolverFactory.SUBSERVICE, SERVICE_NAME))) {
                final JackrabbitSession session = (JackrabbitSession) resolver.adaptTo(Session.class);
                if (session != null) {
                    user = getOrCreateSamlUser(session, samlUser);
                    if (user != null) {
                        updateGroupMembership(session, samlUser, user);
                        updateUserProperties(session, samlUser, user);
                    } else {
                        LOG.error("Could not sync user '{}'; user was null.", userId);
                    }
                } else {
                    LOG.error("Could not sync user '{}'. JackrabbitSession was null.", userId);
                }
            } catch (final LoginException lex) {
                LOG.error("Could not get SAML2 User Service. Check mapping org.apache.sling.auth.saml2:{}=...", SERVICE_NAME);
            } catch (final RepositoryException ex) {
                LOG.error(ex.getMessage(), ex);
            }
        } else {
            LOG.error("SAML2 user has no id set.");
        }
        return user;
    }

    @Nullable
    protected User getOrCreateSamlUser(@Nonnull final JackrabbitSession session, @Nonnull final Saml2User samlUser)
            throws RepositoryException {
        User user = null;
        final String userId = samlUser.getId();
        final UserManager userManager = session.getUserManager();
        final Authorizable authorizable = userManager.getAuthorizable(userId);
        if (authorizable != null) {
            if (!authorizable.isGroup() && authorizable instanceof User) {
                user = (User) authorizable;
            }
        } else {
            final Principal principal = new SimplePrincipal(userId);
            user = userManager.createUser(userId, null, principal, getIntermediatePath(userId));
            session.save();
        }
        return user;
    }

    /**
     * Builds a user intermediate path based on the configured user root with a path inserted which is derived
     * from the users domain if such a domain can be extracted from the given parameter.
     * The domain is inserted at each place marked for domain insertion in the configured user root. Such a
     * domain placeholder is a pattern like '{domain}' in the configured users root with optional characters
     * for domain path appending and domain dot replacement, e.g. '/home/users/external{/domain/}'.
     *
     * @param userIdOrMail the user id or the users mail address (should be like a mail address)
     * @return the intermediat path or 'null' (no itermediate path)
     */
    @Nullable
    protected String getIntermediatePath(@Nonnull final String userIdOrMail) {
        final StringBuilder intermediatePath = new StringBuilder();
        final String userHome = config.saml2userHome();
        if (StringUtils.isNotBlank(userHome)) {
            final Matcher placeholder = DOMAIN.matcher(userHome);
            int offset = 0;
            while (placeholder.find(offset)) {
                intermediatePath.append(userHome, offset, placeholder.start());
                final Matcher identifier = MAIL_ADDR.matcher(userIdOrMail);
                if (identifier.matches()) {
                    final String concat = placeholder.group("concat");
                    final String join = placeholder.group("join");
                    final List<String> path = Arrays.asList(StringUtils.split(identifier.group("domain"), '.'));
                    Collections.reverse(path);
                    if (intermediatePath.length() > 0) {
                        intermediatePath.append(StringUtils.isNotBlank(concat) ? concat : "/");
                    }
                    intermediatePath.append(StringUtils.join(path, StringUtils.isNotBlank(join) ? join : "/"));
                    if (placeholder.end() < userHome.length()) {
                        intermediatePath.append(StringUtils.isNotBlank(concat) ? concat : "/");
                    }
                }
                offset = placeholder.end();
            }
            intermediatePath.append(userHome.substring(offset));
        }
        LOG.debug("intermediate path: '{}'", intermediatePath);
        return intermediatePath.length() > 0 ? intermediatePath.toString() : null;
    }

    protected void updateGroupMembership(@Nonnull final JackrabbitSession session,
                                         @Nonnull final Saml2User samlUser, @Nonnull final User user)
            throws RepositoryException {
        final UserManager userManager = session.getUserManager();
        // iterate all mapped groups
        for (final String groupId : syncGroupMap.values()) {
            Authorizable authorizable = userManager.getAuthorizable(groupId);
            if (authorizable != null && authorizable.isGroup()) {
                Group group = (Group) authorizable;
                if (samlUser.getGroupMembership().contains(groupId)) {
                    if (!group.isMember(user)) {
                        group.addMember(user);
                    }
                } else {
                    if (group.isMember(user)) {
                        group.removeMember(user);
                    }
                }
            }
        }
        session.save();
    }

    protected void updateUserProperties(@Nonnull final JackrabbitSession session,
                                        @Nonnull final Saml2User samlUser, @Nonnull final User user)
            throws RepositoryException {
        ValueFactory valueFactory = session.getValueFactory();
        for (Map.Entry<String, String> entry : samlUser.getUserProperties().entrySet()) {
            user.setProperty(entry.getKey(), valueFactory.createValue(entry.getValue()));
        }
        session.save();
    }

    // helpers

    public static Map<String, String> buildKeyMap(@Nullable final String[] keys) {
        Map<String, String> map = new LinkedHashMap<>();
        if (keys != null) {
            for (String key : keys) {
                if (StringUtils.isNotBlank(key)) {
                    String[] parts = StringUtils.split(key, "=", 2);
                    map.put(parts[0], parts.length > 1 ? parts[1] : parts[0]);
                }
            }
        }
        return map;
    }
}
