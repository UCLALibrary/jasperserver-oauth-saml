/* Copyright 2009 Vladimir Schäfer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * Modified By:Ronald Meadows
 */
package org.springframework.security.saml;

import org.opensaml.common.SAMLException;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.core.NameID;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;

import org.springframework.util.Assert;

/**
 * Authentication provider is capable of verifying validity of a SAMLAuthenticationToken and in case
 * the token is valid to create an authenticated UsernamePasswordAuthenticationToken.
 *
 * @author Vladimir Schäfer 
 */
public class SAMLAuthenticationProvider implements AuthenticationProvider {

    private WebSSOProfileConsumer consumer;

    private final static Logger log = LoggerFactory.getLogger(SAMLAuthenticationProvider.class);
    private SAMLUserDetailsService userDetails;

    /**
     * Default constructor
     * @param consumer profile to use
     */
    public SAMLAuthenticationProvider(WebSSOProfileConsumer consumer) {
        this.consumer = consumer;
    }

    /**
     * Attempts to perform authentication of an Authentication object. The authentication must be of type
     * SAMLAuthenticationToken and must contain filled BasicSAMLMessageContext. If the SAML inbound message
     * in the context is valid, UsernamePasswordAuthenticationToken with name given in the SAML message NameID
     * and assertion used to verify the user as credential are created and set as authenticated.
     * @param authentication SAMLAuthenticationToken to verify
     * @return UsernamePasswordAuthenticationToken with name as NameID value and SAMLCredential as credential object
     * @throws AuthenticationException user can't be authenticated due to an error
     */
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        SAMLAuthenticationToken token = (SAMLAuthenticationToken) authentication;
        BasicSAMLMessageContext context = token.getCredentials();
        log.debug("Saml message retrieved from authentication");
        SAMLCredential credential;

        try {
        	
            credential = consumer.processResponse(context);
        } catch (SAMLException e) {
            throw new AuthenticationServiceException("Error validating SAML message", e);
        } catch (ValidationException e) {
            log.debug("Error validating signature", e);
            throw new AuthenticationServiceException("Error validating SAML message signature", e);
        } catch (org.opensaml.xml.security.SecurityException e) {
            log.debug("Error validating signature", e);
            throw new AuthenticationServiceException("Error validating SAML message signature", e);
        }

        NameID subjectName = (NameID) context.getSubjectNameIdentifier();
        String name = subjectName.getValue();
        return processUserDetails( credential);
    }

    
    protected void  doAfterPropertiesSet() throws Exception {
 Assert.notNull(this.userDetails, "A UserDetailsService must be set");
 }
    /**
     * Populates user data from SAMLCredential into UserDetails object.
     * @param token token to store UserDetails to
     * @param credential credential to load user from 
     */
    protected AbstractAuthenticationToken processUserDetails( SAMLCredential credential) {
        if (getUserDetails() != null) {
        	log.debug("Processing user details");
            UserDetails myuserdetails=getUserDetails().loadUserBySAML(credential);
            if(myuserdetails==null){
            	log.debug("User information returned from service was null. Performing unsuccessful login.");
            	 throw new BadCredentialsException("Bad credentials.  Attribute values were not valid for successful ");
   			     
            }
            log.debug("Populating authentication token with user information.");
            UsernamePasswordAuthenticationToken wrappingAuth = new UsernamePasswordAuthenticationToken(myuserdetails, myuserdetails.getPassword(), myuserdetails.getAuthorities());
          wrappingAuth.setDetails(myuserdetails);
          return wrappingAuth;
        }
        log.debug("UserDetailsService not set. User information cannot be loaded.  User will not be logged in.");
        throw new AuthenticationServiceException("UserDetailsService not set. User information cannot be loaded.  User will not be logged in.");
    }

    /**
     * Returns saml user details service used to load information about logged user from SAML data.
     * @return service or null if not set
     */
    public SAMLUserDetailsService getUserDetails() {
        return userDetails;
    }

    /**
     * The user details can be optionally set and is automatically called while user SAML assertion
     * is validated.
     * @param userDetails user details
     */
    public void setUserDetails(SAMLUserDetailsService userDetails) {
        this.userDetails = userDetails;
    }

    /**
     * SAMLAuthenticationToken is the only supported token.
     * @param aClass class to check for support
     * @return true if class is of type SAMLAuthenticationToken
     */
    public boolean supports(Class aClass) {
        return SAMLAuthenticationToken.class.isAssignableFrom(aClass);
    }

}
