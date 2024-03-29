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

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.apache.commons.lang3.StringUtils;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.sling.auth.core.AuthUtil;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.saml2.AuthenticationHandlerSAML2;
import org.apache.sling.auth.saml2.AuthenticationHandlerSAML2Config;
import org.apache.sling.auth.saml2.Helpers;
import org.apache.sling.auth.saml2.SAML2RuntimeException;
import org.apache.sling.auth.saml2.Saml2User;
import org.apache.sling.auth.saml2.Saml2UserMgtService;
import org.apache.sling.auth.saml2.sp.KeyPairCredentials;
import org.apache.sling.auth.saml2.sp.SamlReason;
import org.apache.sling.auth.saml2.sp.SessionStorage;
import org.apache.sling.auth.saml2.sp.VerifySignatureCredentials;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.SessionIndex;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.SessionIndexBuilder;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.FrameworkUtil;
import org.osgi.framework.wiring.BundleWiring;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.metatype.annotations.Designate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.jcr.RepositoryException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

import static org.opensaml.saml.saml2.core.LogoutRequest.USER_REASON;

@Component(
        service = AuthenticationHandler.class,
        name = AuthenticationHandlerSAML2Impl.SERVICE_NAME,
        configurationPolicy = ConfigurationPolicy.REQUIRE,
        immediate = true,
        property = {"sling.servlet.methods={GET, POST}",
                AuthenticationHandler.PATH_PROPERTY + "={}",
                AuthenticationHandler.TYPE_PROPERTY + "=" + AuthenticationHandlerSAML2Impl.AUTH_TYPE,
                "service.description=SAML2 Authentication Handler",
                "service.ranking:Integer=42",
        })
@Designate(ocd = AuthenticationHandlerSAML2Config.class, factory = true)
public class AuthenticationHandlerSAML2Impl extends AbstractSamlHandler implements AuthenticationHandlerSAML2 {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationHandlerSAML2Impl.class);

    static final String SERVICE_NAME = "org.apache.sling.auth.saml2.AuthenticationHandlerSAML2";

    public static final String AUTH_STORAGE_SESSION_TYPE = "session";
    public static final String AUTH_TYPE = "SAML2";
    static final String TOKEN_FILENAME = "saml2-cookie-tokens.bin";

    @Reference
    private Saml2UserMgtService saml2UserMgtService;

    private SessionStorage storageAuthInfo;
    long sessionTimeout;
    private Credential spKeypair;
    private Credential idpVerificationCert;

    /**
     * The request method required for SAML2 submission (value is "POST").
     * POST_BINDING
     */
    private static final String REQUEST_METHOD = "POST";

    /**
     * The factor to convert minute numbers into milliseconds used internally
     */
    private static final long MINUTES = 60L * 1000L;
    private static final long TIMEOUT_MIN = 240; // 4 hr

    /**
     * The {@link TokenStore} used to persist and check authentication data
     */
    private TokenStore tokenStore;

    @Activate
    @Modified
    protected void activate(final AuthenticationHandlerSAML2Config config, ComponentContext componentContext)
            throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException, IOException {
        this.setConfigs(config);
        final File tokenFile = getTokenFile(componentContext.getBundleContext());
        initializeTokenStore(tokenFile);
        if (this.getSaml2SPEncryptAndSign()) {
            //      set encryption keys
            this.idpVerificationCert = VerifySignatureCredentials.getCredential(
                    this.getJksFileLocation(),
                    this.getJksStorePassword().toCharArray(),
                    this.getIdpCertAlias());
            this.spKeypair = KeyPairCredentials.getCredential(
                    this.getJksFileLocation(),
                    this.getJksStorePassword().toCharArray(),
                    this.getSpKeysAlias(),
                    this.getSpKeysPassword().toCharArray());
            //      set credential for signing
        }
    }

    void initializeTokenStore(File file) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {
        this.storageAuthInfo = new SessionStorage(AUTHENTICATED_SESSION_ATTRIBUTE);
        this.sessionTimeout = MINUTES * TIMEOUT_MIN;
        this.tokenStore = new TokenStore(file, sessionTimeout, false);
    }

    TokenStore getTokenStore() {
        return this.tokenStore;
    }

    Credential getSpKeypair() {
        return this.spKeypair;
    }

    Credential getIdpVerificationCert() {
        return this.idpVerificationCert;
    }

    SessionStorage getStorageAuthInfo() {
        return this.storageAuthInfo;
    }

    /**
     * Extracts session based credentials from the request. Returns
     * <code>null</code> if the secure user data is not present either in the HTTP Session.
     */
    @Override
    public AuthenticationInfo extractCredentials(final HttpServletRequest httpServletRequest,
                                                 final HttpServletResponse httpServletResponse) {
// 0. if disabled return null
        if (!this.getSaml2SPEnabled()) {
            return null;
        }

// 1. If the request is POST to the ACS URL, it needs to extract the Auth Info from the SAML data POST'ed
        final String reqURI = httpServletRequest.getRequestURI();
        if (reqURI.equals(this.getAcsPath())) {
            return processAssertionConsumerService(httpServletRequest);
        }
// 1a. If it's a request to the derived ACS logged out URL the logout cycle should be finalized
        if (reqURI.equals(this.getAcsPath() + "/loggedout")) {
            final String redirectUrl = getPostLogoutRedirect();
            if (StringUtils.isNotBlank(redirectUrl) && !httpServletResponse.isCommitted())
                try {
                    httpServletResponse.sendRedirect(redirectUrl);
                } catch (IOException ex) {
                    logger.error(ex.getMessage(), ex);
                }
            return null;
        }
// else, RequestURI is not the ACS path

// 2.  try credentials from the session
        if (!this.getSaml2Path().isEmpty() && reqURI.startsWith(this.getSaml2Path())) {
            final String authData = getStorageAuthInfo().getString(httpServletRequest);
            if (authData != null) {
                if (tokenStore.isValid(authData)) {
                    return buildAuthInfo(authData);
                } else {
                    // clear the token from the session, its invalid and we should get rid of it
                    // so that the invalid cookie isn't present on the authN operation.
                    clearSessionAttributes(httpServletRequest);

                    if (AuthUtil.isValidateRequest(httpServletRequest)) {
                        // signal the requestCredentials method a previous login failure
                        httpServletRequest.setAttribute(FAILURE_REASON, SamlReason.TIMEOUT);
                        return AuthenticationInfo.FAIL_AUTH;
                    }
                }
            }
        }
        return null;
    }

    private void clearSessionAttributes(final HttpServletRequest httpServletRequest) {
        getStorageAuthInfo().clear(httpServletRequest);
    }

    private AuthenticationInfo processAssertionConsumerService(final HttpServletRequest httpServletRequest) {
        doClassloading();
        MessageContext messageContext = decodeHttpPostSamlResp(httpServletRequest);
        Assertion assertion = null;
        boolean relayStateIsOk = validateRelayState(httpServletRequest, messageContext);
        // If relay state from request == relay state from session))
        logger.debug("processAssertionConsumerService({})...", relayStateIsOk);
        if (relayStateIsOk) {
            Response response = (Response) messageContext.getMessage();
            if (this.getSaml2SPEncryptAndSign()) {
                EncryptedAssertion encryptedAssertion = response.getEncryptedAssertions().get(0);
                assertion = decryptAssertion(encryptedAssertion);
                verifyAssertionSignature(assertion);
            } else {
                // Not using encryption
                assertion = response.getAssertions().get(0);
            }
            if (validateSaml2Conditions(httpServletRequest, assertion)) {
                logger.debug("Decrypted Assertion: ");
                User extUser = doUserManagement(assertion);
                if (extUser != null) {
                    return this.buildAuthInfo(extUser);
                }
            }
            logger.error("Validation of SubjectConfirmation failed");
        }
        return null;
    }

    /**
     * Requests authentication information from the client.
     * Returns true if the information has been requested and request processing can be terminated normally.
     * Otherwise the authorization information could not be requested.
     * <p>
     * The HttpServletResponse.sendError methods should not be used by the implementation because these responses
     * might be post-processed by the servlet container's error handling infrastructure thus preventing the correct operation of the authentication handler.
     * <p>
     * To convey a HTTP response status the HttpServletResponse.setStatus method should be used.
     * <p>
     * The value of PATH_PROPERTY service registration property value triggering this call is available as the path request attribute.
     * If the service is registered with multiple path values, the value of the path request attribute may be used to implement specific handling.
     * <p>
     * If the REQUEST_LOGIN_PARAMETER request parameter is set only those authentication handlers registered with an authentication type matching the parameter will be considered for requesting credentials through this method.
     * <p>
     * A handler not registered with an authentication type will, for backwards compatibility reasons, always be called ignoring the actual value of the REQUEST_LOGIN_PARAMETER parameter.
     * <p>
     * Parameters:
     *
     * @param httpServletRequest  - The request object.
     * @param httpServletResponse - The response object to which to send the request.
     * @throws IOException - If an error occurs sending the authentication inquiry to the client.
     * @returns true if the handler is able to send an authentication inquiry for the given request. false otherwise.
     */
    @Override
    public boolean requestCredentials(final HttpServletRequest httpServletRequest,
                                      final HttpServletResponse httpServletResponse) throws IOException {
        // 0. ignore this handler if an authentication handler is requested
        if (ignoreRequestCredentials(httpServletRequest)) {
            // consider this handler is not used
            return false;
        }

        if (this.getSaml2SPEnabled()) {
            doClassloading();
            HttpSession session = httpServletRequest.getSession(false);
            if (session != null) {
                session.invalidate(); // initiate login with a fresh session
            }
            setGotoURLOnSession(httpServletRequest);
            redirectUserForAuthentication(httpServletRequest, httpServletResponse);
            return true;
        }
        return false;
    }

    void doClassloading() {
        // Classloading
        BundleWiring bundleWiring = FrameworkUtil.getBundle(AuthenticationHandlerSAML2Impl.class).adapt(BundleWiring.class);
        ClassLoader loader = bundleWiring.getClassLoader();
        Thread thread = Thread.currentThread();
        thread.setContextClassLoader(loader);
    }

    private void setGotoURLOnSession(final HttpServletRequest request) {
        SessionStorage sessionStorage = new SessionStorage(GOTO_URL_SESSION_ATTRIBUTE);
        sessionStorage.setString(request, request.getRequestURL().toString());
    }

    private void redirectUserForAuthentication(final HttpServletRequest httpServletRequest,
                                               final HttpServletResponse httpServletResponse) {
        AuthnRequest authnRequest = buildAuthnRequest();
        redirectUserWithRequest(httpServletRequest, httpServletResponse, authnRequest);
    }

    private void redirectUserForSingleLogout(final HttpServletRequest httpServletRequest,
                                             final HttpServletResponse httpServletResponse) {
        Principal principal = httpServletRequest.getUserPrincipal();
        if (principal != null) {
            LogoutRequest logoutRequest = buildLogoutRequest(principal.getName(), null);
            redirectUserWithRequest(httpServletRequest, httpServletResponse, logoutRequest);
        }
    }

    /**
     * Returns <code>true</code> if this authentication handler should ignore the
     * call to {@link #requestCredentials(HttpServletRequest, HttpServletResponse)}.
     * <p>
     * This method returns <code>true</code> if the {@link #REQUEST_LOGIN_PARAMETER}
     * is set to any value other than "SAML2" (the authentication type)
     */
    boolean ignoreRequestCredentials(final HttpServletRequest request) {
        final String requestLogin = request.getParameter(REQUEST_LOGIN_PARAMETER);
        return requestLogin != null && !AUTH_TYPE.equals(requestLogin);
    }

    private void redirectUserWithRequest(final HttpServletRequest httpServletRequest,
                                         final HttpServletResponse httpServletResponse, final RequestAbstractType requestForIDP) {
        MessageContext context = new MessageContext();
        context.setMessage(requestForIDP);
        SAMLBindingContext bindingContext = Objects.requireNonNull(context.getSubcontext(SAMLBindingContext.class, true));
        SAMLPeerEntityContext peerEntityContext = Objects.requireNonNull(context.getSubcontext(SAMLPeerEntityContext.class, true));
        SAMLEndpointContext endpointContext = Objects.requireNonNull(peerEntityContext.getSubcontext(SAMLEndpointContext.class, true));
        if (requestForIDP instanceof AuthnRequest) {
            setRelayStateOnSession(httpServletRequest, bindingContext);
            setRequestIDOnSession(httpServletRequest, (AuthnRequest) requestForIDP);
            endpointContext.setEndpoint(getIPDEndpoint());
        } else if (requestForIDP instanceof LogoutRequest) {
            endpointContext.setEndpoint(getSLOEndpoint());
        }
        SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
        signatureSigningParameters.setSigningCredential(this.getSpKeypair());
        signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        Objects.requireNonNull(context.getSubcontext(SecurityParametersContext.class, true))
                .setSignatureSigningParameters(signatureSigningParameters);
        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
        encoder.setMessageContext(context);
        encoder.setHttpServletResponse(httpServletResponse);

        try {
            encoder.initialize();
        } catch (ComponentInitializationException e) {
            throw new SAML2RuntimeException(e);
        }

        logger.debug("Redirecting to IDP: '{}'", requestForIDP.getID());
        try {
            encoder.encode();
        } catch (MessageEncodingException e) {
            throw new SAML2RuntimeException(e);
        }
    }

    Endpoint getIPDEndpoint() {
        SingleSignOnService endpoint = Helpers.buildSAMLObject(SingleSignOnService.class);
        endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        endpoint.setLocation(this.getSaml2IDPDestination());
        return endpoint;
    }

    Endpoint getSLOEndpoint() {
        SingleLogoutService endpoint = Helpers.buildSAMLObject(SingleLogoutService.class);
        endpoint.setBinding(SAMLConstants.SAML2_PAOS_BINDING_URI);
        endpoint.setLocation(this.getSaml2LogoutURL());
        return endpoint;
    }

    /*
     *
     * Attribution:
     * Created by Privat on 4/6/14.
     *
     * for another Apache 2.0 licensed project.
     * https://bitbucket.org/srasmusson/webprofile-ref-project-v3/src/master/src/main/java/no/steras/opensamlbook/sp/AccessFilter.java
     * https://bitbucket.org/srasmusson/webprofile-ref-project-v3/src/master/src/main/java/no/steras/opensamlbook/sp/ConsumerServlet.java
     */
    AuthnRequest buildAuthnRequest() {
        AuthnRequest authnRequest = Helpers.buildSAMLObject(AuthnRequest.class);
        authnRequest.setIssueInstant(Instant.now());
        authnRequest.setDestination(this.getSaml2IDPDestination());
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        // Entity ID
        authnRequest.setAssertionConsumerServiceURL(this.getACSURL());
        authnRequest.setID(Helpers.generateSecureRandomId());
        authnRequest.setIssuer(buildIssuer());
        authnRequest.setNameIDPolicy(buildNameIdPolicy());
        return authnRequest;
    }

    LogoutRequest buildLogoutRequest(@Nonnull final String userId, @Nullable final String sessionIdx) {
        LogoutRequest logoutRequest = Helpers.buildSAMLObject(LogoutRequest.class);
        logoutRequest.setIssueInstant(Instant.now());
        logoutRequest.setDestination(this.getSaml2LogoutURL());
        // Entity ID
        logoutRequest.setID(Helpers.generateSecureRandomId());
        logoutRequest.setIssuer(buildIssuer());
        // User and Session
        NameID nameId = new NameIDBuilder().buildObject();
        nameId.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
        nameId.setValue(userId);
        logoutRequest.setNameID(nameId);
        if (StringUtils.isNotBlank(sessionIdx)) {
            SessionIndex sessionIndex = new SessionIndexBuilder().buildObject();
            sessionIndex.setSessionIndex(sessionIdx);
            logoutRequest.getSessionIndexes().add(sessionIndex);
        }
        logoutRequest.setReason(USER_REASON);
        return logoutRequest;
    }

    Issuer buildIssuer() {
        Issuer issuer = Helpers.buildSAMLObject(Issuer.class);
        issuer.setValue(this.getEntityID());
        return issuer;
    }

    NameIDPolicy buildNameIdPolicy() {
        NameIDPolicy nameIDPolicy = Helpers.buildSAMLObject(NameIDPolicy.class);
        nameIDPolicy.setAllowCreate(true);
        nameIDPolicy.setFormat(NameIDType.TRANSIENT);
        return nameIDPolicy;
    }

    MessageContext decodeHttpPostSamlResp(final HttpServletRequest request) {
        HTTPPostDecoder httpPostDecoder = new HTTPPostDecoder();
        ParserPool parserPool = XMLObjectProviderRegistrySupport.getParserPool();
        httpPostDecoder.setParserPool(parserPool);
        httpPostDecoder.setHttpServletRequest(request);
        try {
            httpPostDecoder.initialize();
            httpPostDecoder.decode();
            return httpPostDecoder.getMessageContext();
        } catch (MessageDecodingException e) {
            logger.error("MessageDecodingException");
            throw new SAML2RuntimeException(e);
        } catch (ComponentInitializationException e) {
            throw new SAML2RuntimeException(e);
        }
    }

    private Assertion decryptAssertion(final EncryptedAssertion encryptedAssertion) {
        // Use SP Private Key to decrypt
        StaticKeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(getSpKeypair());
        Decrypter decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
        decrypter.setRootInNewDocument(true);
        try {
            return decrypter.decrypt(encryptedAssertion);
        } catch (DecryptionException e) {
            throw new SAML2RuntimeException(e);
        }
    }

    private void verifyAssertionSignature(final Assertion assertion) {
        if (!assertion.isSigned()) {
            logger.error("Halting");
            throw new SAML2RuntimeException("The SAML Assertion was not signed!");
        }
        try {
            SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
            profileValidator.validate(assertion.getSignature());
            // use IDP Cert to verify signature
            SignatureValidator.validate(assertion.getSignature(), this.getIdpVerificationCert());
            logger.info("SAML Assertion signature verified");
        } catch (SignatureException e) {
            throw new SAML2RuntimeException("SAML Assertion signature problem", e);
        }
    }

    /*
     * End Privat attribution
     */

    User doUserManagement(final Assertion assertion) {
        if (assertion == null ||
                assertion.getAttributeStatements().isEmpty() ||
                assertion.getAttributeStatements().get(0).getAttributes().isEmpty()) {
            logger.warn("SAML Assertion Attribute Statement or Attributes was null.");
            return null;
        }
        if (saml2UserMgtService != null) {
            // build and synchronize a user object
            final Saml2User saml2User = new Saml2User();
            saml2UserMgtService.applySaml2Attributes(assertion, saml2User);
            logger.debug("SAML2 user: '{}' ({},{})", saml2User, saml2User.getGroupMembership(), saml2User.getUserProperties());
            return saml2UserMgtService.performUserSynchronization(saml2User);
        }
        logger.warn("No SAML user management service bound.");
        return null;
    }

    AuthenticationInfo buildAuthInfo(final User user) {
        try {
            AuthenticationInfo authInfo = new AuthenticationInfo(AUTH_TYPE, user.getID());
            authInfo.put("user.jcr.credentials", new Saml2Credentials(user.getID()));
            return authInfo;
        } catch (RepositoryException e) {
            logger.error("failed to build Authentication Info");
            throw new SAML2RuntimeException(e);
        }
    }

    AuthenticationInfo buildAuthInfo(final String authData) {
        final String userId = getUserId(authData);
        if (userId == null) {
            return null;
        }
        final AuthenticationInfo info = new AuthenticationInfo(AUTH_TYPE, userId);
        info.put("user.jcr.credentials", new Saml2Credentials(userId));
        return info;
    }

    private void setRelayStateOnSession(HttpServletRequest req, SAMLBindingContext bindingContext) {
        String state = new BigInteger(130, new SecureRandom()).toString(32);
        bindingContext.setRelayState(state);
        SessionStorage sessionStorage = new SessionStorage(this.getSaml2SessionAttr());
        sessionStorage.setString(req, state);
    }

    private void setRequestIDOnSession(HttpServletRequest req, AuthnRequest authnRequest) {
        SessionStorage sessionStorage = new SessionStorage(SAML2_REQUEST_ID);
        sessionStorage.setString(req, authnRequest.getID());
    }

    private boolean validateRelayState(HttpServletRequest req, MessageContext messageContext) {
        SAMLBindingContext bindingContext = messageContext.getSubcontext(SAMLBindingContext.class, true);
        String reportedRelayState = bindingContext.getRelayState();
        SessionStorage relayStateStore = new SessionStorage(this.getSaml2SessionAttr());
        String savedRelayState = relayStateStore.getString(req);
        logger.debug("validate relay state: '{}'=='{}'? ({})", reportedRelayState, savedRelayState, relayStateStore);
        if (savedRelayState == null || savedRelayState.isEmpty()) {
            return false;
        } else if (savedRelayState.equals(reportedRelayState)) {
            return true;
        }
        return false;
    }

    private boolean validateSaml2Conditions(HttpServletRequest req, Assertion assertion) {
        final List<SubjectConfirmation> subjectConfirmations = assertion.getSubject().getSubjectConfirmations();
        if (subjectConfirmations.isEmpty()) {
            return false;
        }
        final SubjectConfirmationData subjectConfirmationData = subjectConfirmations.get(0).getSubjectConfirmationData();
        final Instant notOnOrAfter = subjectConfirmationData.getNotOnOrAfter();
        // validate expiration

        final boolean validTime = notOnOrAfter.isAfter(Instant.now());
        if (!validTime) {
            logger.error("SAML2 Subject Confirmation failed validation: Expired.");
        }
        // validate recipient
        final String recipient = subjectConfirmationData.getRecipient();
        final boolean validRecipient = recipient.equals(this.getACSURL());
        if (!validRecipient) {
            logger.error("SAML2 Subject Confirmation failed validation: Invalid Recipient.");
        }
        // validate In Response To (ID saved in session from authnRequest)
        final String inResponseTo = subjectConfirmationData.getInResponseTo();
        final String savedInResponseTo = new SessionStorage(SAML2_REQUEST_ID).getString(req);
        boolean validID = savedInResponseTo.equals(inResponseTo);

        // return true if subject confirmation is validated
        return validTime && validRecipient && validID;
    }


    private void redirectToGotoURL(HttpServletRequest req, HttpServletResponse resp) {
        String gotoURL = (String) req.getSession().getAttribute(GOTO_URL_SESSION_ATTRIBUTE);
        logger.info("Redirecting to requested URL: {}", gotoURL);
        try {
            resp.sendRedirect(gotoURL);
        } catch (IOException e) {
            throw new SAML2RuntimeException(e);
        }
    }

    /**
     * Drops credential and authentication details from the request and redirects client to a Logout URL.
     *
     * @param httpServletRequest
     * @param httpServletResponse
     * @throws IOException
     */
    @Override
    public void dropCredentials(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        // check that user is authenticated using this handler to support the auth handler cascade for logout also
        final String authData = getStorageAuthInfo().getString(httpServletRequest);
        if (authData != null) {
            clearSessionAttributes(httpServletRequest);
            if (!this.getSaml2LogoutURL().isEmpty()) {
                redirectUserForSingleLogout(httpServletRequest, httpServletResponse);
            }
        }
    }


    /**
     * Called after an unsuccessful login attempt. This implementation makes sure
     * the authentication data is removed either by removing the cookie or by remove
     * the HTTP Session attribute.
     */
    @Override
    public void authenticationFailed(HttpServletRequest request, HttpServletResponse response,
                                     AuthenticationInfo authInfo) {

        /*
         * Note: This method is called if this handler provided credentials which cause
         * a login failure
         */

        // clear authentication data from Cookie or Http Session
        clearSessionAttributes(request);

        // signal the reason for login failure
        request.setAttribute(FAILURE_REASON, SamlReason.INVALID_CREDENTIALS);
    }

    /**
     * Called after successful login with the given authentication info. This
     * implementation ensures the authentication data is set in either the cookie or
     * the HTTP session with the correct security tokens.
     * <p>
     * If no authentication data already exists, it is created. Otherwise if the
     * data has expired the data is updated with a new security token and a new
     * expiry time.
     * <p>
     * If creating or updating the authentication data fails, it is actually removed
     * from the cookie or the HTTP session and future requests will not be
     * authenticated any longer.
     */
    @Override
    public boolean authenticationSucceeded(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationInfo authInfo) {

        /*
         * Note: This method is called if this handler provided credentials which
         * succeeded login into the repository
         */

        // ensure fresh authentication data
        refreshAuthData(request, response, authInfo);

        final boolean result;
        // only consider a resource redirect if this is a POST request to the ACS URL
        if (REQUEST_METHOD.equals(request.getMethod()) &&
                request.getRequestURI().endsWith(this.getAcsPath())) {
            redirectToGotoURL(request, response);
            result = true;
        } else {
            // no redirect, hence continue processing
            result = false;
        }
        // no redirect
        return result;
    }


    /**
     * Ensures the authentication data is set (if not set yet) and the expiry time
     * is prolonged (if auth data already existed).
     * <p>
     * This method is intended to be called in case authentication succeeded.
     *
     * @param request  The current request
     * @param response The current response
     * @param authInfo The authentication info used to successful log in
     */
    void refreshAuthData(final HttpServletRequest request, final HttpServletResponse response,
                         final AuthenticationInfo authInfo) {

        // get current authentication data, may be missing after first login
        String token = getStorageAuthInfo().getString(request);

        // check whether we have to "store" or create the data
        final boolean refreshCookie = needsRefresh(token);

        // add or refresh the stored auth hash
        if (refreshCookie) {
            long expires = System.currentTimeMillis() + this.sessionTimeout;
            try {
                token = tokenStore.encode(expires, authInfo.getUser());
            } catch (InvalidKeyException | IllegalStateException | UnsupportedEncodingException | NoSuchAlgorithmException e) {
                throw new SAML2RuntimeException(e);
            }

            if (token != null) {
                getStorageAuthInfo().setString(request, token);
            } else {
                clearSessionAttributes(request);
            }
        }
    }

    /**
     * Refresh the cookie periodically.
     * Compares current time to saved expiry time
     *
     * @return true or false
     */
    boolean needsRefresh(final String authData) {
        boolean updateCookie = false;
        if (authData == null) {
            updateCookie = true;
        } else {
            String[] parts = TokenStore.split(authData);
            if (parts != null && parts.length == 3) {
                long cookieTime = Long.parseLong(parts[1].substring(1));
                long timeNow = System.currentTimeMillis();
                if (timeNow > cookieTime) {
                    updateCookie = true;
                }
            }
        }
        return updateCookie;
    }

    /**
     * Returns the user id from the authentication data. If the authentication data
     * is a non-<code>null</code> value with 3 fields separated by an @ sign, the
     * value of the third field is returned. Otherwise <code>null</code> is
     * returned.
     * <p>
     * This method is not part of the API of this class and is package private to
     * enable unit tests.
     *
     * @param authData
     * @return
     */
    String getUserId(final String authData) {
        if (authData != null) {
            String[] parts = TokenStore.split(authData);
            if (parts != null) {
                return parts[2];
            }
        }
        return null;
    }

    /**
     * Returns an absolute file indicating the file to use to persist the security
     * tokens.
     * <p>
     * This method is not part of the API of this class and is package private to
     * enable unit tests.
     *
     * @param bundleContext The BundleContext to use to make an relative file absolute
     * @return The absolute file
     */
    File getTokenFile(final BundleContext bundleContext) {
        File tokenFile = bundleContext.getDataFile(TOKEN_FILENAME);
        if (tokenFile == null) {
            final String slingHome = bundleContext.getProperty("sling.home");
            if (slingHome != null) {
                tokenFile = new File(slingHome, TOKEN_FILENAME);
            } else {
                tokenFile = new File(TOKEN_FILENAME);
            }
        }
        return tokenFile.getAbsoluteFile();
    }
}
