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

import org.jfree.util.Log;

import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLRuntimeException;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Filter processes arriving SAML messages by delegating to the WebSSOProfile. After the SAMLAuthenticationToken
 * is obtained, authentication providers are asked to authenticate it.
 *
 * @author Vladimir Schäfer
 */
public class SAMLProcessingFilter
  extends AbstractAuthenticationProcessingFilter
{


  public SAMLProcessingFilter()
  {
    this( DEFAUL_URL );
  }

  protected SAMLProcessingFilter( String defaultFilterProcessesUrl )
  {
    super( defaultFilterProcessesUrl );
    // TODO Auto-generated constructor stub
  }

  /**
   * Profile to delegate SAML parsing to
   */
  private WebSSOProfile webSSOprofile;

  private static final String DEFAUL_URL = "/saml/SSO";

  private final static Logger log = LoggerFactory.getLogger( SAMLProcessingFilter.class );

  /**
   * In case the login attribute is not present it is presumed that the call is made from the remote IDP
   * and contains a SAML assertion which is processed and authenticated.
   *
   * @param request request
   * @return authentication object in case SAML data was found and valid
   * @throws AuthenticationException authentication failture
   */
  @Override
  public Authentication attemptAuthentication( HttpServletRequest request, HttpServletResponse response )
    throws AuthenticationException
  {
    try
    {
      log.debug( "Attempting SAML2 authentiction" );
      BasicSAMLMessageContext samlMessageContext = webSSOprofile.processSSO( request );
      Log.debug( "SSO has been processed and creating auth token from saml message" );
      SAMLAuthenticationToken token = new SAMLAuthenticationToken( samlMessageContext );
      log.debug( "authenticating with saml message context" );
      return getAuthenticationManager().authenticate( token );
    }
    catch ( SAMLException e )
    {
      throw new SAMLRuntimeException( "Incoming SAML message is invalid" );
    }
    catch ( MetadataProviderException e )
    {
      throw new SAMLRuntimeException( "Error determining metadata contracts" );
    }
    catch ( MessageDecodingException e )
    {
      throw new SAMLRuntimeException( "Error deconding incoming SAML message" );
    }
    catch ( org.opensaml.xml.security.SecurityException e )
    {
      throw new SAMLRuntimeException( "Incoming SAML message is invalid" );
    }
  }


  public String getDefaultFilterProcessesUrl()
  {
    return DEFAUL_URL;
  }

  public int getOrder()
  {
    return 5;
  }

  public void setWebSSOprofile( WebSSOProfile webSSOprofile )
  {
    this.webSSOprofile = webSSOprofile;
  }

}
