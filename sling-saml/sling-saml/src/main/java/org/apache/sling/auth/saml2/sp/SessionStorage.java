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

package org.apache.sling.auth.saml2.sp;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * The <code>SessionStorage</code> class provides support to store the
 * authentication data in an HTTP Session.
 * <p>
 * Derivative work from inner class SessionStorage from
 * https://github.com/apache/sling-org-apache-sling-auth-form/blob/master/src/main/java/org/apache/sling/auth/form/impl/FormAuthenticationHandler.java
 */

public class SessionStorage {

    private static final Logger LOG = LoggerFactory.getLogger(SessionStorage.class);

    private final String sessionAttributeName;

    public SessionStorage(final String sessionAttributeName) {
        this.sessionAttributeName = sessionAttributeName;
    }

    /**
     * Setting String Attributes. Store string info in an http session attribute.
     *
     * @param request http request of the user
     * @param info    set the value of the attribute
     */
    public void setString(HttpServletRequest request, String info) {
        HttpSession session = request.getSession();
        session.setAttribute(sessionAttributeName, info);
        LOG.debug("{}.setString({})", getLogId(request), info);
    }

    /**
     * Getting String Attributes
     *
     * @param request http request of the user
     * @return value of the session attribute
     */
    public String getString(HttpServletRequest request) {
        String value = null;
        HttpSession session = request.getSession(false);
        if (session != null) {
            Object attribute = session.getAttribute(sessionAttributeName);
            if (attribute instanceof String) {
                value = (String) attribute;
            }
        }
        LOG.debug("{}.getString: '{}'", getLogId(request), value);
        return value;
    }

    /**
     * Remove this attribute from the http session
     *
     * @param request http request of the user
     */
    public void clear(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(sessionAttributeName);
            LOG.debug("{}.clear", getLogId(request));
        }
    }

    protected String getLogId(HttpServletRequest request) {
        final HttpSession session = request.getSession(false);
        return "@" + StringUtils.substringAfter(super.toString(), "@")
                + ",R:" + StringUtils.substringAfter(request.toString(), "@")
                + ",S#" + (session != null ? session.getId() : "NULL")
                + "{" + sessionAttributeName + "}";
    }

    @Override
    public String toString() {
        return (getClass().getSimpleName() + "@"
                + StringUtils.substringAfter(super.toString(), "@")
                + "{" + sessionAttributeName + "}");
    }
}