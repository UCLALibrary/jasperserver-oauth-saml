package org.springframework.security.saml.userdetails;
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
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.xml.XMLObject;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;


import com.jaspersoft.jasperserver.multipleTenancy.DefaultTenantInfoImpl;
import com.jaspersoft.jasperserver.multipleTenancy.MTUserDetails;

public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService{
	 private final Log log = LogFactory.getLog(this.getClass());

	
	public UserDetails loadUserBySAML(SAMLCredential credential)
			throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		//return null;
		Assertion mya=credential.getAuthenticationAssertion();
		
		//List<AttributeStatement> attributeStatements = mya.getAttributeStatements();
		//TODO parse userdetail information from assertion here and populate variables below
				String username="testsamluser";
		String fullname="testsamluser";
		 username=mya.getSubject().getNameID().getValue();
		 //String lastname=mya.getAttributeStatements().get(0).getAttributes().get(2).getAttributeValues().get(0).getDOM().getChildNodes().item(0).getNodeValue();
		//username=firstname.substring(0,1) + lastname;
		//fullname=firstname + " " + lastname;
		 fullname=username;
		Collection<GrantedAuthority> myroles= new ArrayList<GrantedAuthority>();
		
				//username=findAttributeValue(attributeStatements, "wm-BusinessUnitNumber");
		//assing to default organization
		log.debug("Adding user to default tenant");
		List<MTUserDetails.TenantInfo> mytenants = new Vector<MTUserDetails.TenantInfo>();
		mytenants.add(new DefaultTenantInfoImpl("organization_1", "Organization", "Organization"));		
		
		
			
		SAMLMTUserDetails myuserdetails=createUserDetails(myroles, username, fullname, "", "organization_1", mytenants, "", true);
		log.debug("UserDetails successfully created");
		return myuserdetails;
	}

	private String findAttributeValue(List<AttributeStatement> attributeStatements, String attName) {
		log.debug("Serching for attribute with name:  " + attName);
		for (int i = 0; i < attributeStatements.size(); i++)
		{
			List<Attribute> attributes = attributeStatements.get(i).getAttributes();
			for (int x = 0; x < attributes.size(); x++)
			{
				String strAttributeName = attributes.get(x).getDOM().getAttribute("Name");
				if(strAttributeName.equalsIgnoreCase(attName)){
					log.debug("Attribute Name " + attName + " found." );
				List<XMLObject> attributeValues = attributes.get(x).getAttributeValues();
				for (int y = 0; y < attributeValues.size(); y++)
				{
					String attValue=attributeValues.get(y).getDOM().getTextContent();
					log.debug("Attribute Value " + attValue);
					return attValue;
					//System.out.println(strAttributeName + ": " + strAttributeValue);
				}
				}
			}
		}
		log.debug("Attribue Name " + attName + " not found in SAML Attributes.");
		return null;
	}

	private SAMLMTUserDetails createUserDetails(Collection<GrantedAuthority> grantedAuthorities, String username, String fullname, String pw,  String orgId,  List<MTUserDetails.TenantInfo> mytenants, String email, boolean isActive){
		log.debug("Creating user details");
		SAMLMTUserDetails wrappingUser = new SAMLMTUserDetails(grantedAuthorities,username,mytenants);
		log.debug("Setting username:  " + username);
		wrappingUser.setUsername(username);
		wrappingUser.setPassword(pw);
		wrappingUser.setAccountNonExpired(true);
		wrappingUser.setAccountNonLocked(true);
		wrappingUser.setAuthorities(grantedAuthorities);
		wrappingUser.setCredentialsNonExpired(true);
		wrappingUser.setEnabled(isActive);
		wrappingUser.setEmailAddress(email);
		wrappingUser.setFullName(fullname);
		//check during testing
		wrappingUser.setExternallyDefined(true);
		log.debug("Setting tenant:  " +orgId);
		 wrappingUser.setTenantId(orgId);
		 return wrappingUser;
	}
	
}
