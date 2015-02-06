package com.jaspersoft.jasperserver.ps.OAuth;
/* Copyright 2014 Ronald Meadows
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
* 
*/




import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.InitializingBean;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;


public class OAuthAuthenticationProvider implements AuthenticationProvider, InitializingBean {
		private final static Logger logger = LogManager.getLogger(OAuthAuthenticationProvider.class);

		private OAuthAccessTokenValidatorInterface accessTokenValidator;
	private OAuthUserDetailsService userDetailsService;

		/**
		 * Method called by Spring's ProviderManager to initiate authentication.
		 *
		 * @param authentication
		 * @return
		 * @throws AuthenticationException if SSO token is not validated.
		 */
				//authenticates user or returns exception
	@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			//cast auth token correctly
			final OAuthAuthenticationToken ssoToken = ((OAuthAuthenticationToken) authentication);
			//get ticket, username and password from auth token
			String accessToken = (String)ssoToken.getAccessToken();
			//otherwise call ticketvalidator to validate session id and return user details
			logger.debug("Calling ticketValidator to authenticate user " + ssoToken);
			String userinformation=accessTokenValidator.validate(ssoToken);		
			 UserDetails userDetails = userDetailsService.parseUserDetails(userinformation);
			 if(userDetails==null){
				 throw new AuthenticationServiceException("Error parsing user details from json response");
			 }
			//create successful authentication with userdetails
			return createSuccessAuthentication(accessToken,authentication, userDetails, userDetails.getAuthorities());
			
			
			}

		/**
		 * Creates a successful {@link Authentication} object.<p>Protected so subclasses can override.</p>
		 *
		 * @param authentication that was presented to the provider for validation
		 * @param userDetails that were parsed from SSO server response to ticket validation request.
		 * @param authorities that were loaded from externalUserDetailsService
		 *
		 * @return the successful authentication token
		 */
		//creates successful authentication token with userdetails
		protected Authentication createSuccessAuthentication(String at,Authentication authentication, UserDetails userDetails, Collection<? extends GrantedAuthority> authorities ) {
			OAuthAuthenticationToken ssoAuthenticationToken = new OAuthAuthenticationToken(at,userDetails.getUsername(), userDetails.getPassword(),  authorities);
			//ssoAuthenticationToken.setDetails(authentication.getDetails());
			ssoAuthenticationToken.setDetails(userDetails);
			return ssoAuthenticationToken;
		}

		public OAuthUserDetailsService getUserDetailsService() {
			return userDetailsService;
		}

		public void setUserDetailsService(
				OAuthUserDetailsService userDetailsService) {
			this.userDetailsService = userDetailsService;
		}

		/**
		 * @param authentication
		 * @return true if the provider supports certain class of {@link Authentication}
		 */
		@Override
		public boolean supports(Class authentication) {
			final boolean supportsSsoAuthToken = OAuthAuthenticationToken.class.isAssignableFrom(authentication);
			logger.debug("Provider " + (supportsSsoAuthToken ? "supports" : "does not support") + " authentication with " + authentication.getName());

			if (supportsSsoAuthToken) {
				return true;
			}
			else {
				return false;
			}
		}

		@Override
		public void afterPropertiesSet() throws Exception {
			Assert.notNull(accessTokenValidator, "accessTokenValidator must not be null in SsoAuthenticationProvider.");
		}

		/**
		 * ticketValidator injected via Spring config.
		 * @param ticketValidator
		 */
		public void setAccessTokenValidator(OAuthAccessTokenValidatorInterface ticketValidator) {
			this.accessTokenValidator = ticketValidator;
		}

		
	
}
