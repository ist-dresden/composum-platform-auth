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
package org.apache.sling.auth.saml2;

import org.apache.jackrabbit.api.security.user.User;
import org.opensaml.saml.saml2.core.Assertion;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public interface Saml2UserMgtService {

    /**
     * Extracts all useful attributes from the given SAML2 assertion and applies these attributes to the SAML user.
     *
     * @param assertion the SAML2 assertion object
     * @param samlUser  the SAML user to update
     */
    void applySaml2Attributes(@Nonnull Assertion assertion, @Nonnull Saml2User samlUser);

    /**
     * Makes all user properties if the given SAML user persistent.
     *
     * @param samlUser the prepared SAML user with all information to synchronize
     * @return the JCR user of the given SAML user
     */
    @Nullable
    User performUserSynchronization(@Nonnull final Saml2User samlUser);
}
