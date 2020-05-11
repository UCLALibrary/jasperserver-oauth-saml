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

import java.util.Collection;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import com.jaspersoft.jasperserver.api.JasperServerAPI;


public class OAuthAuthenticationToken extends UsernamePasswordAuthenticationToken {
	
//authentication token object to store authentication information for application
	 

	    private Object accessToken;
	   
		/**
		 * This constructor can be safely used by any code that wishes to create a
		 * <code>UsernamePasswordAuthenticationToken</code>, as the {@link
		 * #isAuthenticated()} will return <code>false</code>.
		 *
		 */
	    public OAuthAuthenticationToken(Object ticket,Object principal, Object credentials) {
			super(principal, credentials);
	        this.accessToken = ticket;
	       
	        
	    }

		/**
		 * This constructor should only be used by <code>AuthenticationManager</code> or <code>AuthenticationProvider</code>
		 * implementations that are satisfied with producing a trusted (ie {@link #isAuthenticated()} = <code>true</code>)
		 * authentication token.
		 *
		 * @param principal
		 * @param credentials
		 * @param authorities
		 */
		public OAuthAuthenticationToken(Object ticket, Object principal,Object credentials,  Collection<? extends GrantedAuthority> authorities) {
			super(principal, credentials, authorities);
			this.accessToken = ticket;
			
		}

		/**
		 *
		 * @return SSO token/ticket
		 */
		public Object getAccessToken() {
			return accessToken;
		}
		
}
