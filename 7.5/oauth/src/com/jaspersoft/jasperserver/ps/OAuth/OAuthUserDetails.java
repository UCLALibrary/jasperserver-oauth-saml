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

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;




import com.jaspersoft.jasperserver.api.metadata.user.domain.Role;
import com.jaspersoft.jasperserver.api.metadata.user.domain.User;
import com.jaspersoft.jasperserver.api.security.externalAuth.ExternalUserDetails;

public class OAuthUserDetails extends ExternalUserDetails implements UserDetails, User,Serializable {

	private Collection<GrantedAuthority> authorities = null;
	private String password = "";
	private String username = "";
	private String company = "";
	private boolean accountNonExpired = false;
	private boolean accountNonLocked = false;
	private boolean credentialsNonExpired = false;
	private boolean enabled = false;
	private List attributes = null;
	private Set roleSet;
	private String fullName = null;
	private String emailAddress = null;
	private boolean externallyDefined = false;
	private Date previousPasswordChangeTime = null;
	private String tenantId = null;


	
public OAuthUserDetails(Collection<GrantedAuthority> auth, String uname){
	super(uname, auth);
	authorities=auth;
	username=uname;
}
	public Collection<GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	public String getPassword() {
		return this.password;
	}

	public String getUsername() {
		return this.username;
	}

	public String getCompany() {
		return company;
	}

	public void setCompany(String company) {
		this.company = company;
	}

	public boolean isAccountNonExpired() {
		return this.accountNonExpired;
	}

	public boolean isAccountNonLocked() {
		return this.accountNonLocked;
	}

	public boolean isCredentialsNonExpired() {
		return this.credentialsNonExpired;
	}

	public boolean isEnabled() {
		return this.enabled;
	}

	public void setAuthorities(Collection<GrantedAuthority> authorities) {
		this.authorities = authorities;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public void setAccountNonExpired(boolean accountNonExpired) {
		this.accountNonExpired = accountNonExpired;
	}

	public void setAccountNonLocked(boolean accountNonLocked) {
		this.accountNonLocked = accountNonLocked;
	}

	public void setCredentialsNonExpired(boolean credentialsNonExpired) {
		this.credentialsNonExpired = credentialsNonExpired;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public List getAttributes() {
		return attributes;
	}

	public void setAttributes(List attrs) {
		attributes = attrs;
	}

	public Set getRoles() {
		return roleSet;
	}

	public void setRoles(Set newRoleSet) {
		roleSet = newRoleSet;
	}

	public void addRole(Role aRole) {
		this.roleSet.add(aRole);
	}

	public void removeRole(Role aRole) {
		this.roleSet.remove(aRole);
	}

	public String getFullName() {
		return this.fullName;
	}

	public void setFullName(String fullName) {
		this.fullName = fullName;
	}

	public String getEmailAddress() {
		return this.emailAddress;
	}

	public void setEmailAddress(String emailAddress) {
		this.emailAddress = emailAddress;
	}

	public boolean isExternallyDefined() {
		return externallyDefined;
	}

	public void setExternallyDefined(boolean externallyDefined) {
		this.externallyDefined = externallyDefined;
	}

	public Set getRoleSet() {
		return roleSet;
	}

	public void setRoleSet(Set roleSet) {
		this.roleSet = roleSet;
	}

	public Date getPreviousPasswordChangeTime() {
		return previousPasswordChangeTime;
	}

	public void setPreviousPasswordChangeTime(Date previousPasswordChangeTime) {
		this.previousPasswordChangeTime = previousPasswordChangeTime;

	}

	public String getTenantId() {

		return this.tenantId;
	}

	public void setTenantId(String tenantId) {
		this.tenantId = tenantId;

	}
	
}
