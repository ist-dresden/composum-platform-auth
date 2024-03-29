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

import org.apache.sling.auth.core.spi.DefaultAuthenticationFeedbackHandler;
import org.apache.sling.auth.saml2.AuthenticationHandlerSAML2Config;

abstract class AbstractSamlHandler extends DefaultAuthenticationFeedbackHandler {

    // OSGI Configs
    private String path;
    private String saml2SessAttr;
    private String saml2IDPDestination;
    private boolean saml2SPEnabled = false;
    private boolean saml2SPEncryptAndSign = false;
    private String entityID;
    private String jksFileLocation;
    private String jksStorePassword;
    private String spKeysAlias;
    private String spKeysPassword;
    private String idpCertAlias;
    private String acsPath;
    private String saml2LogoutURL;
    private String postLogoutRedirect;

    public static final String GOTO_URL_SESSION_ATTRIBUTE = "gotoURL";
    public static final String SAML2_REQUEST_ID = "saml2RequestID";
    public static final String AUTHENTICATED_SESSION_ATTRIBUTE = "authenticated";

    void setConfigs(final AuthenticationHandlerSAML2Config config){
        this.path = config.path();
        this.saml2SessAttr = config.saml2SessionAttr();
        this.saml2SPEnabled = config.saml2SPEnabled();
        this.saml2SPEncryptAndSign = config.saml2SPEncryptAndSign();
        this.saml2IDPDestination = config.saml2IDPDestination();
        this.entityID = config.entityID();
        this.jksFileLocation = config.jksFileLocation();
        this.jksStorePassword = config.jksStorePassword();
        this.spKeysAlias = config.spKeysAlias();
        this.spKeysPassword = config.spKeysPassword();
        this.idpCertAlias = config.idpCertAlias();
        this.acsPath = config.acsPath();
        this.saml2LogoutURL = config.saml2LogoutURL();
        this.postLogoutRedirect = config.postLogoutRedirect();
    }

//    GETTERS
    String getSaml2Path() {
        return this.path;
    }
    String getSaml2SessionAttr() {
        return this.saml2SessAttr;
    }
    String getSaml2IDPDestination() {
        return this.saml2IDPDestination;
    }
    String getEntityID() {
        return this.entityID;
    }
    String getAcsPath() {
        return this.acsPath;
    }
    boolean getSaml2SPEnabled() {
        return this.saml2SPEnabled;
    }
    boolean getSaml2SPEncryptAndSign() {
        return this.saml2SPEncryptAndSign;
    }
    String getSaml2LogoutURL() {
        return this.saml2LogoutURL;
    }
    String getPostLogoutRedirect() {
        return this.postLogoutRedirect;
    }
    String getJksFileLocation() {
        return this.jksFileLocation;
    }
    String getJksStorePassword() {
        return this.jksStorePassword;
    }
    String getSpKeysAlias() {
        return this.spKeysAlias;
    }
    String getSpKeysPassword() {
        return this.spKeysPassword;
    }
    String getIdpCertAlias() {
        return this.idpCertAlias;
    }

    String getACSURL() {
        final String domain = entityID.endsWith("/") ? entityID.substring(0, entityID.length()-1) : entityID;
        return domain + this.getAcsPath();
    }
}
