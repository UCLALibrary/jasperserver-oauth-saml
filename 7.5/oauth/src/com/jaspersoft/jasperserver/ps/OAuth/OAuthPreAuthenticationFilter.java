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

import java.io.IOException;
import java.util.Map;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;

import com.jaspersoft.jasperserver.api.security.externalAuth.ExternalDataSynchronizer;
import com.jaspersoft.jasperserver.api.security.internalAuth.InternalAuthenticationToken;



public class OAuthPreAuthenticationFilter implements InitializingBean, Filter {

	private static Log log = LogFactory.getLog(OAuthPreAuthenticationFilter.class);
	
	private String authorization_location;
	private String client_id;
	private String redirecturl;
	private String token_location;
	private String clientsecret;
	private AuthenticationManager authenticationManager;
	
	
	
	private HttpSession hSession;
	private ExternalDataSynchronizer externalDataSynchronizer;
	private String defaultTargetUrl="/loginsuccess.html";
	private final static Logger logger = LogManager.getLogger(OAuthPreAuthenticationFilter.class);
    private String filterProcessesUrl;
    private String authenticationFailureUrl;
    private String scopes;
    
	public OAuthPreAuthenticationFilter() {

	}

	
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
    	 
    	 logger.debug("Doing normal required Authentication check against filter processes url");
        String uri = request.getRequestURI();
        logger.debug("Checking authentication required for url: " + uri + " query string: " + request.getQueryString());
        int pathParamIndex = uri.indexOf(';');

        if (pathParamIndex > 0) {
            // strip everything after the first semi-colon
            uri = uri.substring(0, pathParamIndex);
        }

        if ("".equals(request.getContextPath())) {
            return uri.endsWith(getFilterProcessesUrl());
        }
        
       
    	 boolean retval=uri.endsWith(request.getContextPath() + getFilterProcessesUrl());
    	 if(!retval)
    	 {
    		 String ticket = (String)request.getParameter("code");
	    	 Authentication auth = SecurityContextHolder.getContext().getAuthentication();
	    	/* if(auth==null){
	    		 return true;
	    	 }
	    	 if (ticket!=null){
	    		 logger.debug("Tickets exists on request therefore re-authenticating.");
	    		 return true;
	    	 }*/
	    	 return retval;
    	 }
       return retval;
    }
    @Override
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {
		Authentication auth = SecurityContextHolder.getContext()
				.getAuthentication();
		//only do SSO if auth is null otherwise it will use the current sessions auth
		
		HttpServletRequest hRequest = (HttpServletRequest) request;
		//boolean isLogin=hRequest.getRequestURI().toLowerCase().contains("login");
		//hResponse = (HttpServletResponse) response;
		hSession = hRequest.getSession();
		HttpServletResponse hResponse=(HttpServletResponse) response;
		String at=null;
	if(!requiresAuthentication(hRequest, hResponse)){
		
			//otherwise we countinue the filter chain
			chain.doFilter(request, response);
			return;
			}
			
			
		//if we didn't get a new accesstoken from our refresh token above
	    //then we need to re-authenticate b/c our accesstoken has expired.
		
		String oauthcode = (String) hRequest.getParameter("code");
		at=(String)hSession.getAttribute("accessToken");
		if(at==null){
			
		
		//if we don't already have an accesstoken from refreshing or anywhere else initialize authorization code and do handshake
		
			// perform oauth handshake
			 at=performOAuthHandshake(hRequest,hResponse,oauthcode);
			
			//handshake returned auth code and not access token so return for redirect in handshake
			if (at == null){
				return;
			}
			//handshake returned accesstoken
			// get access token from session
		}
		log.info("Pulled access token= " + at + " from the session");
		  final OAuthAuthenticationToken authToken = new OAuthAuthenticationToken(at, at, "",  null);
          
		// process user details if there is an accesstoken and only 1 time
		// --thread safe
		  try{
        Authentication newauth= this.getAuthenticationManager().authenticate(authToken);
        SecurityContextHolder.getContext().setAuthentication(newauth);
		  }catch(AuthenticationException e){
			  SecurityContextHolder.getContext().setAuthentication(null);
			  hSession.removeAttribute("accessToken");
			//  hSession.removeAttribute("refreshToken");
			  hResponse.sendRedirect(hRequest.getContextPath()+authenticationFailureUrl);
			  return;
		  }
		  
		if (log.isDebugEnabled()) {
			log.debug("authentication object processed");
		}
		
		try {
			if (!(SecurityContextHolder.getContext().getAuthentication() instanceof InternalAuthenticationToken))
				externalDataSynchronizer.synchronize();
		} catch (RuntimeException e) {
			SecurityContextHolder.getContext().setAuthentication(null);
			hSession.removeAttribute("refreshToken");
			hSession.removeAttribute("accessToken");
			throw e;
		}
		
		//return auth;
		
		hResponse.sendRedirect(hRequest.getContextPath()+defaultTargetUrl);
		return;
		//chain.doFilter(request, response);
	}

	 
	


	
	
	
	// return user's organization information from service endpoint -- if
	// logging in as an organization
	
	

	private String performOAuthHandshake(HttpServletRequest hRequest,  HttpServletResponse hResponse,
			String oauthcode )  {
	
			log.debug("Performing oauth handshake");
			// redirect to get authentication code if first time through and
			// thread safe
				//check refreshtoken and refresh due to activity.
			String refreshToken=(String)hSession.getAttribute("refreshToken");
			//get previous accessToken and validate user with it so that validation check happens in provider/accesstokenvalidator
			 //at=(String)hSession.getAttribute("accessToken");
			//get accesstoken using refresh token
			if(refreshToken!=null){
			String newat=exchangeRefreshTokenForAccessToken(refreshToken);
			if(newat==null){
			//if we can refresh with our refreshtoken b/c our accesstoken has expired then we redirect
				//to authenticate again.
			
				try {
					hSession.removeAttribute("refreshToken");
					hResponse.sendRedirect(hRequest.getContextPath()+filterProcessesUrl);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					hSession.removeAttribute("refreshToken");
					hSession.removeAttribute("accessToken");
					e.printStackTrace();
					return null;
				}
			}
				return newat;
			
			
			}
			
			
			//if we are authenticating for the first time request oauthcode to initiate authorization code flow
			if (oauthcode == null ) {

				//String reqstring=hRequest.getRequestURI()+"?"+hRequest.getQueryString();
				
				OAuthClientRequest authorization_request = null;
				try {
					authorization_request = OAuthClientRequest
							.authorizationLocation(authorization_location).setResponseType("code").setClientId(client_id).setScope(scopes)			
							.setRedirectURI(redirecturl).buildQueryMessage();
				} catch (OAuthSystemException e) {
					// TODO Auto-generated catch block
					hSession.removeAttribute("refreshToken");
					hSession.removeAttribute("accessToken");
					e.printStackTrace();
					return null;
				}
				log.info("Redirecting to :  " + authorization_request.getLocationUri());

				
				
				
				
				try {
					hResponse.sendRedirect(authorization_request.getLocationUri());
					return null;
							} catch (IOException e) {
					// TODO Auto-generated catch block
								hSession.removeAttribute("refreshToken");
								hSession.removeAttribute("accessToken");
					e.printStackTrace();
				}
				
				
				
			}
			
			// we have an auth code...now post to get access token 
			if (oauthcode != null) {

				// OAuthAuthzResponse oar =
				// OAuthAuthzResponse.oauthCodeAuthzResponse(hRequest);
				// oauthcode = oar.getCode();
				return exchangeAuthorizationCodeForAccessToken(oauthcode);
			}
			return null;
	}


	private String exchangeAuthorizationCodeForAccessToken(String oauthcode) {
		log.info("Retrieved authcode " + oauthcode + " from session to retrieve access token.");
		//hRequest.getSession().setAttribute("proc_once_accesstoken", "true");

						
		log.info("Token redirect url that was built:  " + redirecturl);
		log.info("Client id used: " + client_id);
		log.info("Client secret used:  " + clientsecret);
		log.info("Auth code used:  " + oauthcode);
		
		OAuthClient oAuthClient1 = new OAuthClient(new URLConnectionClient());
		OAuthClientRequest accesstoken_request1;
		try {
			accesstoken_request1 = OAuthClientRequest.tokenLocation(token_location)
					.setGrantType(GrantType.AUTHORIZATION_CODE).setClientId(client_id)
					.setClientSecret(clientsecret).setRedirectURI(redirecturl).setCode(oauthcode).buildBodyMessage();
		
		
		
		log.info("Creating oAuthClient object.");
		log.info("Access token url being used: " + accesstoken_request1.getLocationUri());
		
		 Map<String, String> headers = Utils.getBasicAuthorizationHeader(client_id, clientsecret);
		    //headers.put("Content-Type", "application/x-www-form-urlencoded");
		    accesstoken_request1.setHeaders(headers);


		    
		    OAuthJSONAccessTokenResponse oAuthResponse=null;
			
				oAuthResponse = oAuthClient1.accessToken(accesstoken_request1, OAuth.HttpMethod.POST, OAuthJSONAccessTokenResponse.class);
			
		
log.info("accesstoken retreived: " + oAuthResponse.getAccessToken());
hSession.setAttribute("accessToken", oAuthResponse.getAccessToken());
hSession.setAttribute("refreshToken", oAuthResponse.getRefreshToken());
return oAuthResponse.getAccessToken();
			} catch (OAuthSystemException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				hSession.removeAttribute("refreshToken");
				hSession.removeAttribute("accessToken");
				return null;
			} catch (OAuthProblemException e) {
				// TODO Auto-generated catch block
				hSession.removeAttribute("refreshToken");
				hSession.removeAttribute("accessToken");
				e.printStackTrace();
				return null;
			}
	}


	private String exchangeRefreshTokenForAccessToken(String refreshToken) {
		OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
		OAuthClientRequest accesstoken_request;
		try {
			accesstoken_request = OAuthClientRequest.tokenLocation(token_location)
					.setGrantType(GrantType.REFRESH_TOKEN).setClientId(client_id)
					.setClientSecret(clientsecret).setRedirectURI(redirecturl).setRefreshToken(refreshToken).buildBodyMessage();
		
		
		
		log.info("Creating oAuthClient object.");
		log.info("Access token url being used: " + accesstoken_request.getLocationUri());
		
		 Map<String, String> headers = Utils.getBasicAuthorizationHeader(client_id, clientsecret);
		    //headers.put("Content-Type", "application/x-www-form-urlencoded");
		    accesstoken_request.setHeaders(headers);


		    
		    OAuthJSONAccessTokenResponse oAuthResponse = oAuthClient.accessToken(accesstoken_request, OAuth.HttpMethod.POST, OAuthJSONAccessTokenResponse.class);
			
		
log.info("accesstoken retreived: " + oAuthResponse.getAccessToken());
hSession.setAttribute("accessToken", oAuthResponse.getAccessToken());
hSession.setAttribute("refreshToken", oAuthResponse.getRefreshToken());
return oAuthResponse.getAccessToken();
			} catch (OAuthSystemException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				hSession.removeAttribute("refreshToken");
				hSession.removeAttribute("accessToken");
				return null;
				
			} catch (OAuthProblemException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				hSession.removeAttribute("refreshToken");
				hSession.removeAttribute("accessToken");
				return null;
			}
	}


	

	// creates the user details object that gets put into the authentication
	// principal
	

	@Override
	public void afterPropertiesSet() throws Exception {
	
		if (authorization_location == null) {
			log.debug("Authorization Location property not set on SBAuthFilter bean.");
			throw new Exception("Authorization Location property not set on SBAuthFilter bean.");
		}
		if (client_id == null) {
			log.debug("client_id property not set on SBAuthFilter bean.");
			throw new Exception("client_id property not set on SBAuthFilter bean.");
		}
		if (redirecturl == null) {
			log.debug("redirecturl property not set on SBAuthFilter bean.");
			throw new Exception("redirecturl property not set on SBAuthFilter bean.");
		}
		if (token_location == null) {
			log.debug("token_location property not set on SBAuthFilter bean.");
			throw new Exception("token_location property not set on SBAuthFilter bean.");
		}
		if (clientsecret == null) {
			log.debug("clientsecret property not set on SBAuthFilter bean.");
			throw new Exception("clientsecret property not set on SBAuthFilter bean.");
		}
		/*
		if (users_location == null) {
			log.debug("users_location property not set on JugnooAuthFilter bean.");
			throw new Exception("users_location property not set on JugnooAuthFilter bean.");
		}
		if (clients_location == null) {
			log.debug("clients_location property not set on JugnooAuthFilter bean.");
			throw new Exception("clients_location property not set on JugnooAuthFilter bean.");
		}
		if (users_roles_location == null) {
			log.debug("users_roles_location property not set on JugnooAuthFilter bean.");
			throw new Exception("users_roles_location property not set on JugnooAuthFilter bean.");
		}
		*/

	}

	
	

	public String getAuthorization_location() {
		return authorization_location;
	}

	public void setAuthorization_location(String authorization_location) {
		this.authorization_location = authorization_location;
	}

	public String getClient_id() {
		return client_id;
	}

	public void setClient_id(String clientid) {
		this.client_id = clientid;
	}

	public String getRedirecturl() {
		return redirecturl;
	}

	public void setRedirecturl(String redirecturl) {
		this.redirecturl = redirecturl;
	}

	public String getToken_location() {
		return token_location;
	}

	public void setToken_location(String token_location) {
		this.token_location = token_location;
	}

	public String getClientsecret() {
		return clientsecret;
	}

	public void setClientsecret(String clientsecret) {
		this.clientsecret = clientsecret;
	}
/*
	public String getUsers_location() {
		return users_location;
	}

	public void setUsers_location(String users_location) {
		this.users_location = users_location;
	}

	public String getClients_location() {
		return clients_location;
	}

	public void setClients_location(String clients_location) {
		this.clients_location = clients_location;
	}

	public String getUsers_roles_location() {
		return users_roles_location;
	}

	public void setUsers_roles_location(String users_roles_location) {
		this.users_roles_location = users_roles_location;
	}
*/

	public ExternalDataSynchronizer getExternalDataSynchronizer() {
		return externalDataSynchronizer;
	}

	public void setExternalDataSynchronizer(
			ExternalDataSynchronizer externalDataSynchronizer) {
		this.externalDataSynchronizer = externalDataSynchronizer;
	}

	public String getFilterProcessesUrl() {
		return filterProcessesUrl;
	}


	public void setFilterProcessesUrl(String filterProcessesUrl) {
		this.filterProcessesUrl = filterProcessesUrl;
	}


	public String getAuthenticationFailureUrl() {
		return authenticationFailureUrl;
	}


	public void setAuthenticationFailureUrl(String authenticationFailureUrl) {
		this.authenticationFailureUrl = authenticationFailureUrl;
	}


	public String getDefaultTargetUrl() {
		return defaultTargetUrl;
	}


	public void setDefaultTargetUrl(String defaultTargetUrl) {
		this.defaultTargetUrl = defaultTargetUrl;
	}



	public AuthenticationManager getAuthenticationManager() {
		return authenticationManager;
	}


	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}


	public String getScopes() {
		return scopes;
	}


	public void setScopes(String scopes) {
		this.scopes = scopes;
	}


	@Override
	public void destroy() {
		// TODO Auto-generated method stub
		
	}

	
	@Override
	public void init(FilterConfig arg0) throws ServletException {
		// TODO Auto-generated method stub
		
	}
}
