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
 */
package org.springframework.security.saml.assertion;

import org.opensaml.saml2.core.RequestAbstractType;

import java.util.Hashtable;

/**
 * Class provides caching of SAML messages. Messages can be stored and retreived
 * from this class by their ID. The messages are never deleted, a thread performing maintenance
 * of the class needs to be implemented.
 *
 * @author Vladimir Schäfer
 */
public class ProtocolCache
{

  /**
   * Message storage.
   */
  private static Hashtable<String, RequestAbstractType> messages;

  /**
   * Default constructor.
   */
  public ProtocolCache()
  {
    messages = new Hashtable<String, RequestAbstractType>();
  }

  /**
   * Stores a request message into the repository. RequestAbstractType must have an ID
   * set. Any previous message with the same ID will be overwritten.
   * @param request request message
   */
  public void storeMessage( RequestAbstractType request )
  {
    String id = request.getID();
    messages.put( id, request );
  }

  /**
   * Returns previously stored message with the given ID or null, if there is no message
   * stored.
   * @param ID ID of mesage to retreive
   * @return message found or null
   */
  public RequestAbstractType retreiveMessage( String ID )
  {
    return messages.get( ID );
  }

}
