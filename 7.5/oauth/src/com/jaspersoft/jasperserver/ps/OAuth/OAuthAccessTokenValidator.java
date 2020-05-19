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
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthBearerClientRequest;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthResourceResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;


import java.util.Map;

public class OAuthAccessTokenValidator  implements OAuthAccessTokenValidatorInterface {
	
	
	  private String userdetails_key;
		private String userdetails_secret;
		private String userdetails_location;
		private boolean useBearerHeader;
	private static Logger log = LogManager.getLogger(OAuthAccessTokenValidator.class);
	//String query;
	
	//validates session id and returns user detail inormation in provider
@Override
	public String validate(Object ssoToken)
			throws AuthenticationServiceException, BadCredentialsException {
	//check for sso token and throw exception if not present to fall through to next provider
		String accessToken = checkAuthenticationToken(ssoToken);
		
		if (accessToken != null){

			OAuthResourceResponse resourceResponse = validateAccessToken(accessToken);

		if(resourceResponse.getResponseCode()!=200){
			throw new BadCredentialsException("Bad Credentials from oauth endpoint");
		}
			 return resourceResponse.getBody();
		}
		return null;
	}





private String checkAuthenticationToken(Object ssoToken) {
	if (ssoToken == null)
		throw new AuthenticationServiceException("No SSO information available");
	//cast auth token correctly
	OAuthAuthenticationToken mytoken=(OAuthAuthenticationToken) ssoToken;
	//get and check for sessiondata from token and throw exception if not available
	String ticket = (String)mytoken.getAccessToken();
	if (ticket==null || "".equals(ticket.toString().trim()))
		throw new AuthenticationServiceException("No SSO authtoken");
	String username=(String)mytoken.getPrincipal();
	//get and check for u from token and throw exception if not available
	if (username == null || "".equals(username.toString().trim())){
		log.debug("No username passed");
		throw new AuthenticationServiceException("No username passed");
	}
	return ticket;
}





	private OAuthResourceResponse validateAccessToken(String ticket) {
		OAuthResourceResponse resourceResponse =null;
		try {
		
			// Map<String, String> headers = Utils.getBasicAuthorizationHeader(userdetails_key, userdetails_secret);
			 
		    	OAuthClientRequest bearerClientRequest;
		    	if(useBearerHeader){
		    		bearerClientRequest= new OAuthBearerClientRequest(userdetails_location)
		     .setAccessToken(ticket).buildHeaderMessage();
		    	}else{
		    		bearerClientRequest= new OAuthBearerClientRequest(userdetails_location)
				     .setAccessToken(ticket).buildQueryMessage();
		    	}
		    	//bearerClientRequest.setHeaders(headers);
		    	OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());			 
		    	resourceResponse = oAuthClient.resource(bearerClientRequest, OAuth.HttpMethod.GET, OAuthResourceResponse.class);
		
		} catch (OAuthSystemException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new AuthenticationServiceException(e.getMessage());
			
		}catch (OAuthProblemException e){
			e.printStackTrace();
			throw new AuthenticationServiceException(e.getMessage());
		}
		return resourceResponse;
	}





public String getUserdetails_location() {
	return userdetails_location;
}


public void setUserdetails_location(String userdetails_location) {
	this.userdetails_location = userdetails_location;
}


public String getUserdetails_key() {
	return userdetails_key;
}


public void setUserdetails_key(String userdetails_key) {
	this.userdetails_key = userdetails_key;
}


public String getUserdetails_secret() {
	return userdetails_secret;
}


public void setUserdetails_secret(String userdetails_secret) {
	this.userdetails_secret = userdetails_secret;
}





public boolean isUseBearerHeader() {
	return useBearerHeader;
}





public void setUseBearerHeader(boolean useBearerHeader) {
	this.useBearerHeader = useBearerHeader;
}

	
	


	
}
