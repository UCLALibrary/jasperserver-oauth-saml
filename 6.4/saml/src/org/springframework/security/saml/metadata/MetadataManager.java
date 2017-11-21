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
package org.springframework.security.saml.metadata;

import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.ChainingMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.SecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class offering extra services on top of underlaying chaining MetadataProviders. Manager keeps track of all available
 * identity and service providers configured inside the chained metadata providers. Exactly one service provider can
 * be determined as hosted.
 *
 * @author Vladimir Sch�fer
 */
public class MetadataManager extends ChainingMetadataProvider {

    private final Logger log = LoggerFactory.getLogger(MetadataManager.class);

    private String hostedSPName;
    private String defaultIDP;

    /**
     * Set of IDP names available in the system.
     */
    private Set<String> idpName;

    /**
     * Set of SP names available in the system.
     */
    private Set<String> spName;

    public MetadataManager(List<MetadataProvider> providers) throws MetadataProviderException {
        super();
        this.idpName = new HashSet<String>();
        this.spName = new HashSet<String>();
        setProviders(providers);
        initialize();
    }

    /**
     * Method can be repeatedly called to browse all configured providers and load SP and IDP names which
     * are supported by them.
     *
     * @throws MetadataProviderException error parsing data
     */
    protected synchronized void initialize() throws MetadataProviderException {
        idpName.clear();
        spName.clear();
        for (MetadataProvider provider : getProviders()) {
            Set<String> stringSet = parseProvider(provider);
            for (String key : stringSet) {
                RoleDescriptor roleDescriptor;
                roleDescriptor = provider.getRole(key, IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS);
                if (roleDescriptor != null) {
                    idpName.add(key);

                }
                roleDescriptor = provider.getRole(key, SPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS);
                if (roleDescriptor != null) {
                    spName.add(key);
                }
            }
        }
    }

    /**
     * Parses the provider and returns set of entityIDs contained inside the provider.
     *
     * @param provider provider to parse
     * @return set of entityIDs available in the provider
     * @throws MetadataProviderException error
     */
    private Set<String> parseProvider(MetadataProvider provider) throws MetadataProviderException {
        Set<String> result = new HashSet<String>();
        XMLObject object = provider.getMetadata();
        if (object instanceof EntityDescriptor) {
            EntityDescriptor desc = (EntityDescriptor) object;
            String entityID = desc.getEntityID();
            log.debug("Found metadata entity with ID: " + entityID);
            result.add(entityID);
        }
        //MJB added following check in case metadata contains EntitiesDescriptor (generally 
        //indicating multiple EntityDescriptor's). Loop through all of them and get the entity IDs
        if (object instanceof EntitiesDescriptor) {
        	EntitiesDescriptor descriptors = (EntitiesDescriptor) object;
        	List<EntityDescriptor> allEntityDescriptors = descriptors.getEntityDescriptors();
        	String entityID = null;
        	for (EntityDescriptor thisEntityDescriptor : allEntityDescriptors)
        	{
        		entityID = thisEntityDescriptor.getEntityID();
                log.debug("Found metadata entity with ID: " + entityID);
                result.add(entityID);
        	}
        }

        return result;
    }

    /**
     * Returns set of names of all IDPs available in the metadata
     *
     * @return set of entityID naems
     */
    public Set<String> getIDPEntityNames() {
        return Collections.unmodifiableSet(idpName);
    }

    /**
     * Returns set of names of all SPs entity names
     *
     * @return set of SP entity names available in the metadata
     */
    public Set<String> getSPEntityNames() {
        return Collections.unmodifiableSet(spName);
    }

    /**
     * @param idpID name of IDP to chec
     * @return true if IDP entity ID is in the circle of trust with our entity
     */
    public boolean isIDPValid(String idpID) {
        return idpName.contains(idpID);
    }

    /**
     * @param spID entity ID of SP to check
     * @return true if given SP entity ID is valid in circle of trust
     */
    public boolean isSPValid(String spID) {
        return spName.contains(spID);
    }

    /**
     * The method returns name of SP running this application. This name is either set from spring
     * context of automatically by invoking of the metadata filter.
     *
     * @return name of hosted SP metadata which can be returned by call to getEntityDescriptor.
     */
    public String getHostedSPName() {
        return hostedSPName;
    }

    /**
     * Sets nameID of SP hosted on this machine. This can either be called from springContext or
     * automatically during invocation of metadata generation filter.
     *
     * @param hostedSPName name of metadata describing SP hosted on this machine
     */
    public void setHostedSPName(String hostedSPName) {
        this.hostedSPName = hostedSPName;
    }

    /**
     * Returns entity ID of the IDP to be used by default. In case the defaultIDP property has been set
     * it is returned. Otherwise first available IDP in IDP list is used.
     *
     * @return entity ID of IDP to use
     * @throws MetadataProviderException in case IDP can't be determined
     */
    public String getDefaultIDP() throws MetadataProviderException {
        if (defaultIDP != null) {
            return defaultIDP;
        } else {
            Iterator<String> iterator = getIDPEntityNames().iterator();
            if (iterator.hasNext()) {
                return iterator.next();
            } else {
                throw new MetadataProviderException("No IDP was configured, please update included metadata with at least one IDP");
            }
        }
    }

    /**
     * Sets name of IDP to be used as default. In case the IDP is not present (wasn't loaded from any
     * metadata provider) exception is thrown.
     * @param defaultIDP IDP to set as default
     * @throws org.springframework.security.config.SecurityConfigurationException in case the defaultIDP is not configured in the system/
     */
    public void setDefaultIDP(String defaultIDP) throws SecurityException {

        for (String s : getIDPEntityNames()) {
            if (s.equals(defaultIDP)) {
                this.defaultIDP = defaultIDP;
                return;
            }
        }
        
        throw new SecurityException("Attempt to set nonexisting IDP as default: "+defaultIDP);
    }

}
