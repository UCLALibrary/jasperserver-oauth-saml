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
package org.springframework.security.saml.websso;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLRuntimeException;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.validation.ValidationException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.assertion.ProtocolCache;
import org.springframework.security.saml.metadata.MetadataManager;

import java.util.Date;
import java.util.Iterator;
import java.util.List;

/**
 * Class is able to process Response objects returned from the IDP after SP initialized SSO or unsolicited
 * response from IDP. In case the response is correctly validated and no errors are found the SAMLCredential\
 * is created.
 *
 * @author Vladimir Schäfer
 */
public class WebSSOProfileConsumer
{

  private final static Logger log = LoggerFactory.getLogger( WebSSOProfileConsumer.class );

  private ExplicitKeySignatureTrustEngine trustEngine;

  /**
   * Maximum time from response creation when the message is deemed valid
   */
  private int DEFAULT_RESPONSE_SKEW = 60;

  /**
   * Maximum time between assertion creation and current time when the assertion is usable
   */
  private static int MAX_ASSERTION_TIME = 3000;

  /**
   * Maximum time between user's authentication and current time
   */
  private static int MAX_AUTHENTICATION_TIME = 7200;

  /**
   * Trust engine used to verify SAML signatures
   */
  /*
     * Cache storing SAML request objects
     */
  private ProtocolCache protocolCache;
  private boolean checkSubjectLocality;

  protected static final String BEARER_CONFIRMATION = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
  //begin RKM
  private KeyStoreCredentialResolver keyManager;
  private String decryptionKey;

  //end RKM


  /**
   * Initializes the authentication provider
   * @param metadata metadata manager
   * @throws MetadataProviderException error initializing the provider
   */
  public WebSSOProfileConsumer( MetadataManager metadata, KeyStoreCredentialResolver keyManager, String decryptionKey )
    throws MetadataProviderException
  {
    //Credential sigverificationCredential= getIDPSignatureVerificationCredential();

    MetadataCredentialResolver mdCredResolver = new MetadataCredentialResolver( metadata );
    KeyInfoCredentialResolver keyInfoCredResolver =
      Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver();
    trustEngine = new ExplicitKeySignatureTrustEngine( mdCredResolver, keyInfoCredResolver );

    this.decryptionKey = decryptionKey;
    this.keyManager = keyManager;

  }

  /**
   * The inpuc context object must have set the properties related to the returned Response, which is validated
   * and in case no errors are found the SAMLCredentail is returned.
   * @param context context including response object
   * @return SAMLCredential with information about user
   * @throws SAMLException in case the response is invalid
   * @throws org.opensaml.xml.security.SecurityException in the signature on response can't be verified
   * @throws ValidationException in case the response structure is not conforming to the standard
   */
  public SAMLCredential processResponse( BasicSAMLMessageContext context )
    throws SAMLException, org.opensaml.xml.security.SecurityException, ValidationException
  {

    AuthnRequest request = null;
    SAMLObject message = context.getInboundSAMLMessage();


    // Verify type
    if ( !( message instanceof Response ) )
    {
      log.debug( "Received response is not of a Response object type" );
      throw new SAMLException( "Error validating SAML response. Received response is not of a Response object type" );
    }
    Response response = ( Response ) message;
    log.debug( "Processing saml response" );
    // Verify status
    if ( !StatusCode.SUCCESS_URI.equals( response.getStatus().getStatusCode().getValue() ) )
    {
      String[] logMessage = new String[ 2 ];
      logMessage[ 0 ] = response.getStatus().getStatusCode().getValue();
      StatusMessage message1 = response.getStatus().getStatusMessage();
      if ( message1 != null )
      {
        logMessage[ 1 ] = message1.getMessage();
      }
      log.debug( "Received response has invalid status code and is not success code", logMessage );
      throw new SAMLException( "SAML status is not success code" );
    }


    // Verify signature of the response if present
    if ( response.getSignature() != null )
    {
      log.debug( "Verifying Response signature" );
      boolean validsig = verifySignature( response.getSignature(), context.getPeerEntityId() );
      if ( !validsig )
      {
        throw new SAMLException( "Response signature did not validate.  User will not be logged in." );
      }
    }

    // Verify issue time
    DateTime time = response.getIssueInstant();
    if ( !isDateTimeSkewValid( DEFAULT_RESPONSE_SKEW, time, "Response" ) )
    {
      log.debug( "Response issue time is either too old or with date in the future:  " + time.toString() );
      throw new SAMLException( "Error validating SAML response.  Response issue time is either too old or a date in the future." );
    }

    // Verify response to field if present, set request if correct
    if ( response.getInResponseTo() != null )
    {
      RequestAbstractType requestType = protocolCache.retreiveMessage( response.getInResponseTo() );
      if ( requestType == null )
      {
        log.debug( "InResponseToField doesn't correspond to sent message", response.getInResponseTo() );
        throw new SAMLException( "Error validating SAML response. InResponseToField doesn't correspond to sent message." );
      }
      else if ( requestType instanceof AuthnRequest )
      {
        request = ( AuthnRequest ) requestType;
      }
      else
      {
        log.debug( "Sent request was of different type then received response", response.getInResponseTo() );
        throw new SAMLException( "Error validating SAML response. Sent request was of different type then received response." );
      }
    }

    // Verify destination
    if ( response.getDestination() != null )
    {
      SPSSODescriptor localDescriptor = ( SPSSODescriptor ) context.getLocalEntityRoleMetadata();

      // Check if destination is correct on this SP
      List<AssertionConsumerService> services = localDescriptor.getAssertionConsumerServices();
      boolean found = false;
      for ( AssertionConsumerService service : services )
      {
        log.debug( "Response Destination:  " + response.getDestination() );
        log.debug( "Service location retrieved:  " + service.getLocation() );
        log.debug( "Inbound SAML Protocol:  " + context.getInboundSAMLProtocol() );
        log.debug( "Service binding:  " + service.getBinding() );
        if ( response.getDestination().equals( service.getLocation() ) &&
             context.getInboundSAMLProtocol().equals( service.getBinding() ) )
        {
          found = true;
          break;
        }
      }
      if ( !found )
      {
        log.debug( "Destination of the response was not the expected value", response.getDestination() );
        throw new SAMLException( "Error validating SAML response  Destination of the response was not the expected value." );
      }
    }

    // Verify issuer
    if ( response.getIssuer() != null )
    {
      Issuer issuer = response.getIssuer();
      verifyIssuer( issuer, context );
    }

    Assertion subjectAssertion = null;

    //RKM  if we have encrpted assertions decrypt and process them otherwise assertions aren't encrypted and
    //verify normally
    if ( response.getEncryptedAssertions().size() > 0 )
    {
      // Verify assertions

      subjectAssertion = handleEncryptedAssertions( context, request, response, subjectAssertion );
    }
    else
    {
      subjectAssertion = handleRegularAssertions( context, request, response, subjectAssertion );
    }
    //END RKM
    // Make sure that at least one assertion contains authentication statement and subject with bearer cofirmation
    if ( subjectAssertion == null )
    {
      log.debug( "Response doesn't contain authentication statement" );
      throw new SAMLException( "Error validating SAML response  Response doesn't contain authentication statement." );
    }
    log.debug( "Assertion correctly handled and retrieved" );
    log.debug( "Creating SAMLCedential from subject name and assertion" );
    return new SAMLCredential( subjectAssertion.getSubject().getNameID(), subjectAssertion,
                               context.getPeerEntityMetadata().getEntityID() );
  }
  /*
 * author:  ron meadows
 * RKM
 *
 */
  private Assertion handleEncryptedAssertions( BasicSAMLMessageContext context, AuthnRequest request, Response response,
                                               Assertion subjectAssertion )
    throws SAMLException, SecurityException, ValidationException
  {
    log.debug( "Handling encrypted assertion" );
    List<EncryptedAssertion> assertionList = response.getEncryptedAssertions();
    Assertion b = null;
    for ( EncryptedAssertion a : assertionList )
    {
      b = decryptAssertion( a );

      verifyAssertion( b, request, context );
      /* if (b.getAuthnStatements().size() > 0) {
            	log.debug("Assertion subject: " + b.getSubject());
            	boolean hasSubjConfirmations= (b.getSubject().getSubjectConfirmations() != null);
            	log.debug("Has subject confirmations:  " + hasSubjConfirmations);
                if (b.getSubject() != null && hasSubjConfirmations) {
                	
                    for (SubjectConfirmation conf : b.getSubject().getSubjectConfirmations()) {
                    	log.debug("Subject confirmation: " + conf.getMethod());
                        if (BEARER_CONFIRMATION.equals(conf.getMethod())) {
                        	log.debug("Bearer Confirmation subject assertion found and returned.");
                            subjectAssertion = b;
                        }
                    }
                }
            }
            */
    }
    //return subjectAssertion;
    return b;
  }

  /*
	 * author: ron meadows
	 * RKM
	 *
	 */
  private Assertion handleRegularAssertions( BasicSAMLMessageContext context, AuthnRequest request, Response response,
                                             Assertion subjectAssertion )
    throws SAMLException, SecurityException, ValidationException
  {
    log.debug( "Handling normal non-encrypted assertion" );
    List<Assertion> assertionList = response.getAssertions();
    Assertion b = null;
    for ( Assertion a : assertionList )
    {
      verifyAssertion( a, request, context );
      b = a;

      /*
            if (a.getAuthnStatements().size() > 0) {
            	log.debug("Assertion subject: " + a.getSubject());
            	boolean hasSubjConfirmations= (a.getSubject().getSubjectConfirmations() != null);
            	log.debug("Has subject confirmations:  " + hasSubjConfirmations);
                if (a.getSubject() != null && hasSubjConfirmations) {
                    for (SubjectConfirmation conf : a.getSubject().getSubjectConfirmations()) {
                    	log.debug("Subject confirmation: " + conf.getMethod());
                        if (BEARER_CONFIRMATION.equals(conf.getMethod())) {
                        	log.debug("Bearer Confirmation subject assertion found and returned.");
                            subjectAssertion = a;
                        }
                    }
                }
            }
            */
    }
    //return subjectAssertion;
    return b;
  }

  private void verifyAssertion( Assertion assertion, AuthnRequest request, BasicSAMLMessageContext context )
    throws AuthenticationException, SAMLException, org.opensaml.xml.security.SecurityException, ValidationException
  {
    // Verify assertion time skew
    if ( !isDateTimeSkewValid( MAX_ASSERTION_TIME, assertion.getIssueInstant(), "Assertion" ) )
    {
      log.debug( "Authentication statement is too old to be used", assertion.getIssueInstant() );
      throw new CredentialsExpiredException( "Users authentication credential is too old to be used" );
    }

    // Verify validity of assertion
    // Advice is ignored, core 574
    verifyIssuer( assertion.getIssuer(), context );
    boolean validsig = verifyAssertionSignature( assertion.getSignature(), context );
    if ( !validsig )
    {
      throw new SAMLException( "Assertion signature did not validate. User will not be logged in." );
    }
    verifySubject( assertion.getSubject(), request, context );
    // Assertion with authentication statement must contain audience restriction
    if ( assertion.getAuthnStatements().size() > 0 )
    {
      verifyAssertionConditions( assertion.getConditions(), context, true );
      for ( AuthnStatement statement : assertion.getAuthnStatements() )
      {
        verifyAuthenticationStatement( statement, context );
      }
    }
    else
    {
      verifyAssertionConditions( assertion.getConditions(), context, false );
    }
    log.debug( "Assertion validated successfully" );
  }

  /**
   * Verifies validity of Subject element, only bearer confirmation is validated.
   * @param subject subject to validate
   *
   * @param request request
   * @param context context
   * @throws SAMLException error validating the object
   */
  protected void verifySubject( Subject subject, AuthnRequest request, BasicSAMLMessageContext context )
    throws SAMLException
  {
    boolean confirmed = false;
    log.debug( "Verifying subject element" );

    for ( SubjectConfirmation confirmation : subject.getSubjectConfirmations() )
    {
      if ( BEARER_CONFIRMATION.equals( confirmation.getMethod() ) )
      {

        SubjectConfirmationData data = confirmation.getSubjectConfirmationData();

        // Bearer must have confirmation 554
        if ( data == null )
        {
          log.debug( "Assertion invalidated by missing confirmation data" );
          throw new SAMLException( "SAML Assertion is invalid.  Missing confirmation data" );
        }

        // Not before forbidden by core 558
        if ( data.getNotBefore() != null )
        {
          log.debug( "Assertion contains not before in bearer confirmation, which is forbidden" );
          throw new SAMLException( "SAML Assertion is invalid.  Assertion contains not before in bearer confirmation" );
        }

        // Validate not on or after
        if ( data.getNotOnOrAfter().isBeforeNow() )
        {
          confirmed = false;
          continue;
        }

        // Validate in response to
        if ( request != null )
        {
          if ( data.getInResponseTo() == null )
          {
            log.debug( "Assertion invalidated by subject confirmation - missing inResponseTo field" );
            throw new SAMLException( "SAML Assertion is invalid" );
          }
          else
          {
            if ( !data.getInResponseTo().equals( request.getID() ) )
            {
              log.debug( "Assertion invalidated by subject confirmation - invalid in response to" );
              throw new SAMLException( "SAML Assertion is invalid.  Missing inResponseTo field" );
            }
          }
        }

        // Validate recipient
        if ( data.getRecipient() == null )
        {
          log.debug( "Assertion invalidated by subject confirmation - recipient is missing in bearer confirmation" );
          throw new SAMLException( "SAML Assertion is invalid.  Recipient is missing in bearer confirmation" );
        }
        else
        {
          SPSSODescriptor spssoDescriptor = ( SPSSODescriptor ) context.getLocalEntityRoleMetadata();
          for ( AssertionConsumerService service : spssoDescriptor.getAssertionConsumerServices() )
          {
            if ( context.getInboundSAMLProtocol().equals( service.getBinding() ) &&
                 service.getLocation().equals( data.getRecipient() ) )
            {
              confirmed = true;
            }
          }
        }
      }
      // Was the subject confirmed by this confirmation data? If so let's store the subject in context.
      if ( confirmed )
      {
        log.debug( "Subject confirmed by confirmation data" );
        context.setSubjectNameIdentifier( subject.getNameID() );
        return;
      }
    }

    log.debug( "Assertion invalidated by subject confirmation - can't be confirmed by bearer method" );
    throw new SAMLException( "SAML Assertion is invalid.  Can't be confirmed by bearer method" );
  }

  /**
   * Verifies signature of the assertion. In case signature is not present and SP required signatures in metadata
   * the exception is thrown.
   * @param signature signature to verify
   * @param context context
   * @throws SAMLException signature missing although required
   * @throws org.opensaml.xml.security.SecurityException signature can't be validated
   * @throws ValidationException signature is malformed
   */
  protected boolean verifyAssertionSignature( Signature signature, BasicSAMLMessageContext context )
    throws SAMLException, org.opensaml.xml.security.SecurityException, ValidationException
  {
    SPSSODescriptor roleMetadata = ( SPSSODescriptor ) context.getLocalEntityRoleMetadata();
    log.debug( "Verifying assertion signature." );
    boolean wantSigned = roleMetadata.getWantAssertionsSigned();
    if ( signature != null && wantSigned )
    {
      boolean validsig = verifySignature( signature, context.getPeerEntityMetadata().getEntityID() );
      return validsig;
    }
    else if ( wantSigned )
    {
      log.debug( "Assertion must be signed, but is not" );
      throw new SAMLException( "SAML Assertion is invalid.  Assertion must be signed, but is not" );
    }
    return false;
  }

  protected void verifyIssuer( Issuer issuer, BasicSAMLMessageContext context )
    throws SAMLException
  {
    // Validat format of issuer
    log.debug( "Verifying issuer" );

    if ( issuer.getFormat() != null && !issuer.getFormat().equals( NameIDType.ENTITY ) )
    {
      log.debug( issuer.getFormat() );
      log.debug( "Assertion invalidated by issuer type", issuer.getFormat() );
      throw new SAMLException( "SAML Assertion is invalid.  Assertion invalidated by issuer type" );
    }

    // Validate that issuer is expected peer entity

    if ( !context.getPeerEntityMetadata().getEntityID().equals( issuer.getValue() ) )
    {
      log.debug( "Metadata entity id:  " + context.getPeerEntityMetadata().getEntityID() );
      log.debug( "Issuer entity id:  " + issuer.getValue() );
      log.debug( "Assertion invalidated by unexpected issuer value", issuer.getValue() );
      throw new SAMLException( "SAML Assertion is invalid  Assertion invalidated by unexpected issuer value." );
    }


  }
  /*
    * author:  ron meadows
    * RKM
    * gets decrypting credentials for decrypting assertions
    * should be sp's priv key for the public key they supply to IDP
    * keymanager and key are set as properties of this consumers constructor.
    *
    *
    */

  private Credential getSPDecryptingCredential()
  {
    CriteriaSet cs = new CriteriaSet();
    EntityIDCriteria criteria = new EntityIDCriteria( decryptionKey );
    cs.add( criteria );
    Iterator<Credential> credentialIterator = null;
    try
    {
      credentialIterator = keyManager.resolve( cs ).iterator();
    }
    catch ( Exception e )
    {
      log.error( "Exception occured resolving decryption key for alias:  " + decryptionKey );
      log.debug( e.getMessage() );
    }
    if ( credentialIterator != null && credentialIterator.hasNext() )
    {
      log.debug( "Decryption key successfully resolved from keystore." );
      return credentialIterator.next();
    }
    else
    {
      log.error( "Key with ID '" + decryptionKey + "' wasn't found in the configured key store" );
      throw new SAMLRuntimeException( "Key with ID '" + decryptionKey + "' wasn't found in the configured key store" );
    }
  }


  /*author:  ron meadows
     * RKM
     * handled decrypting assertions pulling credentials from the keymanager property using the supplied keystore/priv key password
     *
     *
     *
     */
  protected Assertion decryptAssertion( EncryptedAssertion encryptedAssertion )
  {
    try
    {

      X509Credential decryptionCredential = ( X509Credential ) getSPDecryptingCredential();
      log.debug( "Decryption credential found for cert:  " + decryptionKey );


      StaticKeyInfoCredentialResolver skicr = new StaticKeyInfoCredentialResolver( decryptionCredential );

      //create a decrypter
      log.debug( "Creating decrypter object." );
      Decrypter decrypter = new Decrypter( null, skicr, new InlineEncryptedKeyResolver() );
      decrypter.setRootInNewDocument( true );

      return decryptSAMLAssertion( encryptedAssertion, decrypter );

    }
    catch ( Exception e )
    {
      return null;
    }
  }
  /*
   * author:  ron meadows
   * RKM
   * decrypts a single saml assertion using the supplied decrypter
   *
   */
  private Assertion decryptSAMLAssertion( EncryptedAssertion encryptedAssertion, Decrypter decrypter )
  {
    log.debug( "Attempting to decrypt assertion" );
    try
    {

      return decrypter.decrypt( encryptedAssertion );

    }
    catch ( DecryptionException de )
    {
      log.error( "Assertion decryption failed." );
      log.error( de.getMessage() );
      return null;
    }


  }

  protected boolean verifySignature( Signature signature, String IDPEntityID )
    throws org.opensaml.xml.security.SecurityException, ValidationException
  {
    SAMLSignatureProfileValidator validator = new SAMLSignatureProfileValidator();
    validator.validate( signature );
    CriteriaSet criteriaSet = new CriteriaSet();
    criteriaSet.add( new EntityIDCriteria( IDPEntityID ) );
    criteriaSet.add( new MetadataCriteria( IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS ) );
    criteriaSet.add( new UsageCriteria( UsageType.SIGNING ) );
    log.debug( "Verifying signature", signature );
    trustEngine.validate( signature, criteriaSet );

    //no validation exception was thrown
    log.debug( "Signature is valid." );
    return true;
  }

  protected void verifyAssertionConditions( Conditions conditions, BasicSAMLMessageContext context,
                                            boolean audienceRequired )
    throws SAMLException
  {
    // If no conditions are implied, assertion is deemed valid
    log.debug( "Verifying assertion conditions" );
    if ( conditions == null )
    {
      return;
    }


    if ( conditions.getNotBefore() != null )
    {
      if ( conditions.getNotBefore().isAfterNow() )
      {
        log.debug( "Assertion is not yet valid, invalidated by condition notBefore", conditions.getNotBefore() );
        throw new SAMLException( "SAML response is not valid.  Invalidated by condition notBefore" );
      }
    }

    if ( conditions.getNotOnOrAfter() != null )
    {
      if ( conditions.getNotOnOrAfter().isBeforeNow() )
      {
        log.debug( "Assertion is no longer valid, invalidated by condition notOnOrAfter",
                   conditions.getNotOnOrAfter() );
        throw new SAMLException( "SAML response is not valid.  Invalidated by condition notOnOrAfter" );
      }
    }

    if ( audienceRequired && conditions.getAudienceRestrictions().size() == 0 )
    {
      log.debug( "Assertion invalidated by missing audience restriction" );
      throw new SAMLException( "SAML response is not valid.  Missing audience restriction" );
    }

    audience:
    for ( AudienceRestriction rest : conditions.getAudienceRestrictions() )
    {
      if ( rest.getAudiences().size() == 0 )
      {
        log.debug( "No audit audience specified for the assertion" );
        throw new SAMLException( "SAML response is invalid.  No audit audience specified for the assertion" );
      }
      for ( Audience aud : rest.getAudiences() )
      {
        log.debug( "Local EntityId:  " + context.getLocalEntityId() );
        log.debug( "Audience uri:  " + aud.getAudienceURI() );
        if ( context.getLocalEntityId().equals( aud.getAudienceURI() ) )
        {
          continue audience;
        }
      }
      log.debug( "Our entity is not the intended audience of the assertion" );
      throw new SAMLException( "SAML response is not intended for this entity" );
    }

    /** ? BUG
         if (conditions.getConditions().size() > 0) {
         log.debug("Assertion contain not understood conditions");
         throw new SAMLException("SAML response is not valid");
         }
         */
  }

  protected void verifyAuthenticationStatement( AuthnStatement auth, BasicSAMLMessageContext context )
    throws AuthenticationException
  {
    // Validate that user wasn't authenticated too long time ago
    log.debug( "Verifying authentication statement." );
    if ( !isDateTimeSkewValid( MAX_AUTHENTICATION_TIME, auth.getAuthnInstant(), "Authentication" ) )
    {
      log.debug( "Authentication statement is too old to be used", auth.getAuthnInstant() );
      log.debug( "Authentication Instant:  " + auth.getAuthnInstant() );
      log.debug( "Max auth time in seconds: " + MAX_AUTHENTICATION_TIME );
      throw new CredentialsExpiredException( "Users authentication data is too old" );
    }
    log.debug( "Authentication instant is withing MAX_AUTHENTICATION_TIME" );
    // Validate users session is still valid

    if ( auth.getSessionNotOnOrAfter() != null && auth.getSessionNotOnOrAfter().isBeforeNow() )
    {
      log.debug( "Validating users session from auth assertion" );
      log.debug( "Session NotOnOrAfter:  " + auth.getSessionNotOnOrAfter() );

      log.debug( "Authentication session is not valid anymore", auth.getSessionNotOnOrAfter() );
      throw new CredentialsExpiredException( "Users authentication is expired" );
    }
    log.debug( "Users sessions is valid" );
    log.debug( "CheckSubjectLocality boolean value: " + checkSubjectLocality );
    if ( auth.getSubjectLocality() != null && checkSubjectLocality )
    {
      log.debug( "Checking subject locality address against peer address" );
      HTTPInTransport httpInTransport = ( HTTPInTransport ) context.getInboundMessageTransport();
      if ( auth.getSubjectLocality().getAddress() != null )
      {
        log.debug( "Verifying authentication statement addresses." );
        log.debug( "Peer Address form httpInTransport:  " + httpInTransport.getPeerAddress() );
        log.debug( "Auth subject locality address:  " + auth.getSubjectLocality().getAddress() );
        if ( !httpInTransport.getPeerAddress().equals( auth.getSubjectLocality().getAddress() ) )
        {
          throw new BadCredentialsException( "User is accessing the service from invalid address" );
        }
      }
    }
    log.debug( "Authentication statement validated successfully" );
  }

  private boolean isDateTimeSkewValid( int skewInSec, DateTime time, String descriptor )
  {

    DateTime current_dt_utcValue = new DateTime().withZone( DateTimeZone.UTC );
    log.debug( "Comparing current_time_stamp:  " + current_dt_utcValue.toString() + " " + descriptor + " timestamp:  " +
               time.toString() );
    log.debug( "Time window in seconds:  " + skewInSec );
    log.debug( "Validating  timestamp is " + skewInSec + " before " + current_dt_utcValue.toString() + " OR " +
               skewInSec + " after " + current_dt_utcValue.toString() );
    return time.isAfter( current_dt_utcValue.getMillis() - skewInSec * 1000 ) &&
           time.isBefore( current_dt_utcValue.getMillis() + DEFAULT_RESPONSE_SKEW * 1000 );
  }


  /**
   * Sets the system wide cache for sent/received assertions.
   * @param protocolCache cache
   */
  public void setProtocolCache( ProtocolCache protocolCache )
  {
    this.protocolCache = protocolCache;
  }


  public String getDecryptionKey()
  {
    return decryptionKey;
  }

  public void setDecryptionKey( String decryptionKey )
  {
    this.decryptionKey = decryptionKey;
  }


  public int getDEFAULT_RESPONSE_SKEW()
  {
    return DEFAULT_RESPONSE_SKEW;
  }

  public void setDEFAULT_RESPONSE_SKEW( int dEFAULT_RESPONSE_SKEW )
  {
    DEFAULT_RESPONSE_SKEW = dEFAULT_RESPONSE_SKEW;
  }

  public boolean getCheckSubjectLocality()
  {
    return checkSubjectLocality;
  }

  public void setCheckSubjectLocality( boolean checkSubjectLocality )
  {
    this.checkSubjectLocality = checkSubjectLocality;
  }

}
