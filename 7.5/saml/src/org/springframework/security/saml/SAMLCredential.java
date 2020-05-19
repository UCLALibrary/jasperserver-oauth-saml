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
 */
package org.springframework.security.saml;

import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Assertion;

/**
 * Object is a storage for entities parsedd from SAML2 response during it's authentication. The object is stored
 * as credential object inside the Authentication returned after authentication success.
 *
 * @author Vladimir Sch�fer
 */
public class SAMLCredential
{

  private NameID nameID;
  private Assertion authenticationAssertion;
  private String IDPEntityID;

  /**
   * Created unmodifiable SAML credential object.
   * @param nameID name ID of the authenticated entity
   * @param authenticationAssertion assertion used to validate the entity
   * @param IDPEntityID identifier of IDP where the assertion came from
   */
  public SAMLCredential( NameID nameID, Assertion authenticationAssertion, String IDPEntityID )
  {
    this.nameID = nameID;
    this.authenticationAssertion = authenticationAssertion;
    this.IDPEntityID = IDPEntityID;

  }

  /**
   * NameID returned from IDP as part of the authentication process.
   * @return name id
   */
  public NameID getNameID()
  {
    return nameID;
  }

  /**
   * Assertion issued by IDP as part of the authentication process.
   * @return assertion
   */
  public Assertion getAuthenticationAssertion()
  {
    return authenticationAssertion;
  }

  /**
   * Entity ID of the IDP which issued the assertion.
   * @return IDP entity ID
   */
  public String getIDPEntityID()
  {
    return IDPEntityID;
  }
}
