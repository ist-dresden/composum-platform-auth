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

import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

/**
 * The configuration for the <code>SAML2</code> user mapping
 *
 * @see Saml2UserMgtServiceImpl
 */
@ObjectClassDefinition(name = "SAML2 User Mapping Configuration")
public @interface Saml2UserMgtServiceConfig {

    @AttributeDefinition(name = "Default Group Memberships",
            description = "Map of group names / identifiers which has to be added to each imported external user.")
    String[] defaultGroups() default {};

    @AttributeDefinition(name = "User ID (uid) Attribute Name",
            description = "Name of the attribute holding the users unique id")
    String saml2userIDAttr() default "username";

    @AttributeDefinition(name = "Path for SAML2 Users",
            description = "Home path for SAML2 Users, optional with a domain placeholder, e.g. '/home/users/external{domain}'")
    String saml2userHome() default "/home/users/saml";

    @AttributeDefinition(name = "Group Membership Attribute Name",
            description = "Name of the attribute holding the users group memberships")
    String saml2groupMembershipAttr() default "";

    @AttributeDefinition(name = "Synchronize Group Memberships",
            description = "Map of group names / identifiers mapped from external identity provider. For example 'external=sling-external' maps IDP group 'external' to Sling group 'sling-external'")
    String[] syncGroups() default {};

    @AttributeDefinition(name = "Synchronize User Attributes",
            description = "Map of attributes from SAML Response to Synchronize. For example, urn:oid:1.2.840.113549.1.9.1=./profile/email saves this attribute if it exists under the users profile node with the property name 'email' ")
    String[] syncAttrs() default {};
}
