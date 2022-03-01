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
 *
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
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


@Component(service = {Saml2UserMgtService.class}, immediate = true)
public class Saml2UserMgtServiceImpl implements Saml2UserMgtService {

    @Reference
    private ResourceResolverFactory resolverFactory;
    private ResourceResolver resourceResolver;
    private Session session;
    private UserManager userManager;
    private ValueFactory vf;
    private static Logger logger = LoggerFactory.getLogger(Saml2UserMgtServiceImpl.class);
    public static final String SERVICE_NAME = "Saml2UserMgtService";
    public static final String SERVICE_USER = "saml2-user-mgt";

    @Override
    public boolean setUp() {
        try {
            Map<String, Object> param = new HashMap<>();
            param.put(ResourceResolverFactory.SUBSERVICE, SERVICE_NAME);
            this.resourceResolver = resolverFactory.getServiceResourceResolver(param);
            if (Objects.isNull(this.getResourceResolver())) {
                logger.error("Could not setup Saml2UserMgtService. Problem with Service User.");
                return false;
            }
            logger.info(this.resourceResolver.getUserID());
            session = this.resourceResolver.adaptTo(Session.class);
            JackrabbitSession jrSession = (JackrabbitSession) session;
            if (Objects.isNull(jrSession)) {
                logger.error("Could not setup Saml2UserMgtService. JackrabbitSession was null.");
                return false;
            }
            userManager = jrSession.getUserManager();
            vf = this.session.getValueFactory();
            return true;
        } catch (LoginException e) {
            logger.error("Could not get SAML2 User Service \r\n" +
                    "Check mapping org.apache.sling.auth.saml2:{}={}", SERVICE_NAME, SERVICE_USER, e);
        } catch (RepositoryException e) {
            logger.error("RepositoryException", e);
        }
        return false;
    }

    ResourceResolver getResourceResolver() {
        return this.resourceResolver;
    }

    void setResolverFactory(ResourceResolverFactory resourceResolverFactory) {
        this.resolverFactory = resourceResolverFactory;
    }

    ResourceResolverFactory getResolverFactory() {
        return this.resolverFactory;
    }

    @Override
    public void cleanUp() {
        resourceResolver.close();
        session = null;
        userManager = null;
        vf = null;
    }

    @Override
    public User getOrCreateSamlUser(Saml2User user) {
        User jackrabbitUser;
        try {
            // find and return the user if it exists
            Authorizable authorizable = userManager.getAuthorizable(user.getId());
            jackrabbitUser = (User) authorizable;
            if (jackrabbitUser != null) {
                return jackrabbitUser;
            }
            jackrabbitUser = userManager.createUser(user.getId(), null);
            session.save();
            return jackrabbitUser;
        } catch (RepositoryException e) {
            logger.error("Could not get User", e);
        }
        return null;
    }

    @Override
    public User getOrCreateSamlUser(Saml2User user, String userHome) {
        User jackrabbitUser;
        try {
            // find and return the user if it exists
            Authorizable authorizable = userManager.getAuthorizable(user.getId());
            jackrabbitUser = (User) authorizable;
            if (jackrabbitUser != null) {
                return jackrabbitUser;
            }
            // if Saml2 User Home is configured, then create a principle
            final String userId = user.getId();
            Principal principal = new SimplePrincipal(userId);
            jackrabbitUser = userManager.createUser(userId, null, principal, getIntermediatePath(userHome, userId));
            session.save();
            return jackrabbitUser;
        } catch (RepositoryException e) {
            logger.error("Could not get User", e);
        }
        return null;
    }

    public static final String USERS_ROOT = "/home/users/";
    public static final Pattern DOMAIN = Pattern.compile("\\{(?<concat>.)?domain(?<join>.)?}");
    public static final Pattern MAIL_ADDR = Pattern.compile("^[^@]+@(?<domain>[^@]+)$");

    protected @Nullable
    String getIntermediatePath(@Nullable final String userHome, @Nonnull final String userIdOrMail) {
        final StringBuilder intermediatePath = new StringBuilder();
        if (StringUtils.isNotBlank(userHome)) {
            final Matcher placeholder = DOMAIN.matcher(userHome);
            int offset = 0;
            while (placeholder.find(offset)) {
                intermediatePath.append(userHome, offset, placeholder.start());
                final Matcher identifier = MAIL_ADDR.matcher(userIdOrMail);
                if (identifier.matches()) {
                    final List<String> path = Arrays.asList(StringUtils.split(identifier.group("domain"), '.'));
                    Collections.reverse(path);
                    if (intermediatePath.length() > 0) {
                        final String concat = placeholder.group("concat");
                        intermediatePath.append(StringUtils.isNotBlank(concat) ? concat : "/");
                    }
                    final String join = placeholder.group("join");
                    intermediatePath.append(StringUtils.join(path, StringUtils.isNotBlank(join) ? join : "/"));
                }
                offset = placeholder.end();
            }
            intermediatePath.append(userHome.substring(offset));
        }
        return intermediatePath.length() > 0 ? intermediatePath.toString() : null;
    }

    @Override
    public boolean updateGroupMembership(Saml2User user) {
        // get list of groups from assertion (see ConsumerServlet::doUserManagement)
        try {
            User jcrUser = (User) this.userManager.getAuthorizable(user.getId());
            if (jcrUser != null) {
                // get and iterate all groups
                for (final String groupId : user.getGroupMembership()) {
                    Authorizable authorizable = userManager.getAuthorizable(groupId);
                    if (authorizable != null && authorizable.isGroup()) {
                        Group group = (Group) authorizable;
                        if (!group.isMember(jcrUser)) {
                            group.addMember(jcrUser);
                        }
                    }
                }
                session.save();
            }
            return true;
        } catch (RepositoryException e) {
            logger.error("RepositoryException", e);
            return false;
        }
    }

    @Override
    public boolean updateUserProperties(Saml2User user) {
        try {
            User jcrUser = (User) this.userManager.getAuthorizable(user.getId());
            for (Map.Entry<String, String> entry : user.getUserProperties().entrySet()) {
                jcrUser.setProperty(entry.getKey(), vf.createValue(entry.getValue()));
            }
            session.save();
            return true;
        } catch (RepositoryException e) {
            logger.error("User Properties could not synchronize", e);
            return false;
        }
    }
}
