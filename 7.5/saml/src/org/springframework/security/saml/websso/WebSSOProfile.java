/* Copyright 2009 Vladimir Sch�fer
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
package org.springframework.security.saml.websso;

import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;

import org.jfree.util.Log;

import org.joda.time.DateTime;

import org.opensaml.Configuration;
import org.opensaml.common.*;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.decoding.BaseSAML2MessageDecoder;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.metadata.*;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.security.criteria.EntityIDCriteria;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.saml.assertion.ProtocolCache;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.util.SAMLUtil;

import com.jaspersoft.jasperserver.ps.SSLOFFLOADHTTPPostDecoder;
import com.jaspersoft.jasperserver.ps.SSLOFFLOADHTTPRedirectDeflateDecoder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.Iterator;
import java.util.Random;

/**
 * Class implements WebSSO profile and offers capabilities for SP initialized SSO and
 * process Response coming from IDP or IDP initialized SSO. HTTP-POST and HTTP-Redirect
 * bindings are supported.
 *
 * @author Vladimir Sch�fer
 */
public class WebSSOProfile
{

  /**
   * Class logger.
   */
  private final static Logger log = LoggerFactory.getLogger( WebSSOProfile.class );

  private MetadataManager metadata;
  private KeyStoreCredentialResolver keyManager;
  private XMLObjectBuilderFactory builderFactory;
  private String signingKey;
  private VelocityEngine velocityEngine;
  private ProtocolCache protocolCache;
  private ParserPool parser;

  private static final int DEFAULT_PROXY_COUNT = 2;

  /**
   * Initializes the profile.
   *
   * @param metadata   metadata manager to be used
   * @param keyManager key manager
   * @param signingKey alias of key used for signing of assertions by local entity
   * @throws SAMLException error initializing the profile
   */
  public WebSSOProfile( MetadataManager metadata, KeyStoreCredentialResolver keyManager, String signingKey )
    throws SAMLException
  {
    this.metadata = metadata;
    this.builderFactory = Configuration.getBuilderFactory();
    this.keyManager = keyManager;
    this.signingKey = signingKey;
    try
    {
      velocityEngine = new VelocityEngine();
      velocityEngine.setProperty( RuntimeConstants.ENCODING_DEFAULT, "UTF-8" );
      velocityEngine.setProperty( RuntimeConstants.OUTPUT_ENCODING, "UTF-8" );
      velocityEngine.setProperty( RuntimeConstants.RESOURCE_LOADER, "classpath" );
      velocityEngine.setProperty( "classpath.resource.loader.class",
                                  "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader" );

      ///MJB added the following 3 lines so velocity will log to JRS logger, not it's own
      //This address issues when we can't create/write to velocity.log on startup due to permissions
      velocityEngine.setProperty( "runtime.log.logsystem.class",
                                  "org.apache.velocity.runtime.log.SimpleLog4JLogSystem" );
      velocityEngine.setProperty( "runtime.log.logsystem.log4j.category", "velocity" );
      velocityEngine.setProperty( "runtime.log.logsystem.log4j.logger", "velocity" );

      velocityEngine.init();
    }
    catch ( Exception e )
    {
      log.debug( "Error initializing velicoity engige", e );
      throw new SAMLException( "Error configuring velocity", e );
    }
  }

  /**
   * Initializes SSO by creating AuthnRequest assertion and sending it to the IDP using the default binding.
   * Default IDP is used to send the request.
   *
   * @param request  request
   * @param response response
   * @throws SAMLException             error initializing SSO
   * @throws MetadataProviderException error retreiving needed metadata
   * @throws MessageEncodingException  error forming SAML message
   */
  public void initializeSSO( HttpServletRequest request, HttpServletResponse response )
    throws SAMLException, MetadataProviderException, MessageEncodingException
  {
    initializeSSO( null, metadata.getDefaultIDP(), request, response );
  }

  /**
   * Initializes SSO by creating AuthnRequest assertion and sending it to the IDP using the default binding.
   * Specified IDP is used to send the request.
   *
   * @param idp      name of IDP to authenticate agains
   * @param request  request
   * @param response response
   * @throws SAMLException             error initializing SSO
   * @throws MetadataProviderException error retreiving needed metadata
   * @throws MessageEncodingException  error forming SAML message
   */
  public void initializeSSO( String idp, HttpServletRequest request, HttpServletResponse response )
    throws SAMLException, MetadataProviderException, MessageEncodingException
  {
    initializeSSO( null, idp, request, response );
  }

  /**
   * Initializes SSO by creating AuthnRequest assertion and sending it to the IDP using the given binding.
   * IDP specified by an argument is used to send the assertion.
   *
   * @param binding  binding to use
   * @param idpId    IDP to send the request to
   * @param request  request
   * @param response response
   * @throws SAMLException             error initializing SSO
   * @throws MetadataProviderException error retreiving needed metadata
   * @throws MessageEncodingException  error forming SAML message
   */
  public void initializeSSO( String binding, String idpId, HttpServletRequest request, HttpServletResponse response )
    throws SAMLException, MetadataProviderException, MessageEncodingException
  {

    if ( !metadata.isIDPValid( idpId ) )
    {
      log.debug( "Given IDP name is not valid", idpId );
      throw new MetadataProviderException( "IDP with name " + idpId + " wasn't found in the list of configured IDPs" );
    }

    EntityDescriptor idpEntityDescriptor = metadata.getEntityDescriptor( idpId );
    IDPSSODescriptor idpssoDescriptor =
      ( IDPSSODescriptor ) metadata.getRole( idpId, IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS );

    SPSSODescriptor spDescriptor =
      ( SPSSODescriptor ) metadata.getRole( metadata.getHostedSPName(), SPSSODescriptor.DEFAULT_ELEMENT_NAME,
                                            SAMLConstants.SAML20P_NS );

    // Find default binding in case none is specified
    if ( binding == null )
    {
      binding = SAMLUtil.getDefaultBinding( idpssoDescriptor );
    }
    
    log.error( "checking response contents" );
    for ( String theHeader : response.getHeaderNames() )
      log.error( "header " + theHeader + " has value " + response.getHeader( theHeader ) );
    
    AssertionConsumerService assertionConsubmerForBinding =
      SAMLUtil.getAssertionConsubmerForBinding( spDescriptor, binding );
    SingleSignOnService bindingService = SAMLUtil.getServiceForBinding( idpssoDescriptor, binding );
    AuthnRequest authRequest = getAuthnRequest( idpEntityDescriptor, assertionConsubmerForBinding, bindingService );

    // TODO optionally implement support for passive, forceauthn, authncontext, conditions, nameIDpolicy, subject

    BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject> samlContext =
      new BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject>();
    samlContext.setOutboundMessageTransport( new HttpServletResponseAdapter( response, false ) );
    samlContext.setOutboundSAMLMessage( authRequest );
    samlContext.setPeerEntityEndpoint( bindingService );

    if ( idpssoDescriptor.getWantAuthnRequestsSigned() )
    {
      samlContext.setOutboundSAMLMessageSigningCredential( getSPSigningCredential() );
    }

    boolean messageSent = false;

    // Send the request using given binding
    if ( binding.equals( SAMLConstants.SAML2_POST_BINDING_URI ) )
    {
      HTTPPostEncoder encoder = new HTTPPostEncoder( velocityEngine, "/templates/saml2-post-binding.vm" );
      encoder.encode( samlContext );
      messageSent = true;
    }
    else if ( binding.equals( SAMLConstants.SAML2_REDIRECT_BINDING_URI ) )
    {
      HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
      encoder.encode( samlContext );
      messageSent = true;
    }

    if ( messageSent )
    {
      //if(log.isDebugEnabled()){
      // SAMLUtil.debugprintSAMLObject(authRequest);
      //}
      protocolCache.storeMessage( authRequest );
    }
    else
    {
      throw new SAMLException( "Given binding is not supported" );
    }
  }

  /**
   * Processes the SSO response or IDP initialized SSO and creates SAMLMessageContext object with the
   * unmarshalled response.
   *
   * @param request request
   * @return SAML message context with filled information about the message
   * @throws SAMLException             error retreiving the message from the request
   * @throws MetadataProviderException error retreiving metadat
   * @throws MessageDecodingException  error decoding the message
   * @throws org.opensaml.xml.security.SecurityException
   *                                   error verifying message
   */
  public BasicSAMLMessageContext processSSO(HttpServletRequest request) throws SAMLException, MetadataProviderException, MessageDecodingException, org.opensaml.xml.security.SecurityException {

      BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject> samlContext = 
      		new BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject>();
      samlContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));
      log.debug("Metadata:  Set LocalEntityRole:  " + SPSSODescriptor.DEFAULT_ELEMENT_NAME);
      samlContext.setLocalEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
      samlContext.setMetadataProvider(metadata);
      samlContext.setLocalEntityId(metadata.getHostedSPName());
      log.debug("Metadata:  Set LocalEntityId: " + metadata.getHostedSPName());
      samlContext.setLocalEntityRoleMetadata(metadata.getRole(metadata.getHostedSPName(), SPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
      log.debug("Metadata:  Set LocalEntityMetadata:  " + metadata.getEntityDescriptor(metadata.getHostedSPName()) );
      samlContext.setLocalEntityMetadata(metadata.getEntityDescriptor(metadata.getHostedSPName()));
     
      BaseSAML2MessageDecoder decoder;
      log.debug("Request method received:  " + request.getMethod());
      if (request.getMethod().equals("POST")) {
      	log.debug("Setting inbound SAML Protocol: " + SAMLConstants.SAML2_POST_BINDING_URI );
          samlContext.setInboundSAMLProtocol(SAMLConstants.SAML2_POST_BINDING_URI);
          decoder = new SSLOFFLOADHTTPPostDecoder(parser);
      } else if (request.getMethod().equals("GET")) {
      	log.debug("Setting inbound SAML Protocol: " + SAMLConstants.SAML2_REDIRECT_BINDING_URI );
          samlContext.setInboundSAMLProtocol(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
          decoder = new SSLOFFLOADHTTPRedirectDeflateDecoder(parser);
         
      } else {
          throw new SAMLException("Unsupported request");
      }
      log.debug("Attempting to decode SAML using decoder.");
      decoder.decode(samlContext);
      log.debug("Successfully decoded SAML");
      log.debug("Metadata:  Set PeerEntityRole:  " + IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
      samlContext.setPeerEntityRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
      samlContext.setPeerEntityId(metadata.getDefaultIDP());
      samlContext.setPeerEntityMetadata(metadata.getEntityDescriptor(metadata.getDefaultIDP()));
      samlContext.setPeerEntityId(samlContext.getPeerEntityMetadata().getEntityID());

      return samlContext;

  }


  /**
   * Returns Credential object used to sign the message issued by this entity.
   * Public, X509 and Private keys are set in the credential.
   *
   * @return credential
   */
  private Credential getSPSigningCredential()
  {
    CriteriaSet cs = new CriteriaSet();
    EntityIDCriteria criteria = new EntityIDCriteria( signingKey );
    cs.add( criteria );
    Iterator<Credential> credentialIterator = null;
    try
    {
      credentialIterator = keyManager.resolve( cs ).iterator();
    }
    catch ( Exception e )
    {
      log.error( "Exception occured resolving signing key for alias:  " + signingKey );
      log.debug( e.getMessage() );
    }
    if ( credentialIterator != null && credentialIterator.hasNext() )
    {
      log.debug( "Signing key successfully resolved from keystore." );
      return credentialIterator.next();
    }
    else
    {
      log.error( "Key with ID '" + signingKey + "' wasn't found in the configured key store" );
      throw new SAMLRuntimeException( "Key with ID '" + signingKey + "' wasn't found in the configured key store" );
    }
  }

  /**
   * Returns AuthnRequest SAML message to be used to demand authentication from an IDP descibed using
   * idpEntityDescriptor, with an expected reponse to the assertionConsumber address.
   *
   * @param idpEntityDescriptor entity descriptor of IDP this request should be sent to
   * @param assertionConsumber  assertion consumer where the IDP should respond
   * @param bindingService      service used to deliver the request
   * @return authnRequest ready to be sent to IDP
   * @throws SAMLException             error creating the message
   * @throws MetadataProviderException error retreiving metadata
   */
  protected AuthnRequest getAuthnRequest( EntityDescriptor idpEntityDescriptor,
                                          AssertionConsumerService assertionConsumber,
                                          SingleSignOnService bindingService )
    throws SAMLException, MetadataProviderException
  {

    SAMLObjectBuilder<AuthnRequest> builder =
      ( SAMLObjectBuilder<AuthnRequest> ) builderFactory.getBuilder( AuthnRequest.DEFAULT_ELEMENT_NAME );
    AuthnRequest request = builder.buildObject();

    request.setID( generateID() );
    buildCommonAttributes( request, bindingService );
    buildIssuer( request );
    buildScoping( request, idpEntityDescriptor, bindingService, true );
    buildReturnAddress( request, assertionConsumber );

    return request;
  }

  /**
   * Generates random ID to be used as Request/Response ID.
   *
   * @return random ID
   */
  private String generateID()
  {
    Random r = new Random();
    return 'a' + Long.toString( Math.abs( r.nextLong() ), 20 ) + Long.toString( Math.abs( r.nextLong() ), 20 );
  }

  /**
   * Fills the request with version, issueinstants and destination data.
   *
   * @param request request to be filled
   * @param service service to use as destination for the request
   */
  private void buildCommonAttributes( RequestAbstractType request, SingleSignOnService service )
  {
    request.setVersion( SAMLVersion.VERSION_20 );
    request.setIssueInstant( new DateTime() );
    request.setDestination( service.getLocation() );
  }

  /**
   * Fills the request with assertion consumer service url and protocol binding based on assertionConsumer
   * to be used to deliver response from the IDP.
   *
   * @param request request
   * @param service service to deliver response to
   * @throws MetadataProviderException error retreiving metadata information
   */
  private void buildReturnAddress( AuthnRequest request, AssertionConsumerService service )
    throws MetadataProviderException
  {
    request.setVersion( SAMLVersion.VERSION_20 );
    request.setAssertionConsumerServiceURL( service.getLocation() );
    request.setProtocolBinding( service.getBinding() );
  }

  /**
   * Fills the request with issuer type, with data about our local entity.
   *
   * @param request request
   */
  private void buildIssuer( RequestAbstractType request )
  {
    SAMLObjectBuilder<Issuer> issuerBuilder =
      ( SAMLObjectBuilder<Issuer> ) builderFactory.getBuilder( Issuer.DEFAULT_ELEMENT_NAME );
    Issuer issuer = issuerBuilder.buildObject();
    issuer.setValue( metadata.getHostedSPName() );
    request.setIssuer( issuer );
  }

  /**
   * Fills the request with information about scoping, including IDP in the scope IDP List.
   *
   * @param request             request to fill
   * @param idpEntityDescriptor idp descriptor
   * @param serviceURI          destination to send the request to
   * @param allowProxy          if true proxying will be allowed on the request
   */
  private void buildScoping( AuthnRequest request, EntityDescriptor idpEntityDescriptor, SingleSignOnService serviceURI,
                             boolean allowProxy )
  {

    SAMLObjectBuilder<IDPEntry> idpEntryBuilder =
      ( SAMLObjectBuilder<IDPEntry> ) builderFactory.getBuilder( IDPEntry.DEFAULT_ELEMENT_NAME );
    IDPEntry idpEntry = idpEntryBuilder.buildObject();
    idpEntry.setProviderID( idpEntityDescriptor.getEntityID() );
    idpEntry.setLoc( serviceURI.getLocation() );

    SAMLObjectBuilder<IDPList> idpListBuilder =
      ( SAMLObjectBuilder<IDPList> ) builderFactory.getBuilder( IDPList.DEFAULT_ELEMENT_NAME );
    IDPList idpList = idpListBuilder.buildObject();
    idpList.getIDPEntrys().add( idpEntry );

    SAMLObjectBuilder<Scoping> scopingBuilder =
      ( SAMLObjectBuilder<Scoping> ) builderFactory.getBuilder( Scoping.DEFAULT_ELEMENT_NAME );
    Scoping scoping = scopingBuilder.buildObject();
    scoping.setIDPList( idpList );

    if ( allowProxy )
    {
      scoping.setProxyCount( new Integer( DEFAULT_PROXY_COUNT ) );
    }

    request.setScoping( scoping );
  }

  /**
   * Setter for protocol cache object.
   *
   * @param protocolCache protocol cache to set
   */
  public void setProtocolCache( ProtocolCache protocolCache )
  {
    this.protocolCache = protocolCache;
  }

  /**
   * Setter for the parser pool object
   *
   * @param parser parser pool
   */
  public void setParser( ParserPool parser )
  {
    this.parser = parser;
  }
}
