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



import com.jaspersoft.jasperserver.multipleTenancy.MTUserDetails;



import java.io.Serializable;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;

public class OAuthMTUserDetails extends OAuthUserDetails implements MTUserDetails,Serializable {

    private List<TenantInfo> tenantList;
    private String accessToken;
    
    public OAuthMTUserDetails(Collection<GrantedAuthority> authorities, String username, List<TenantInfo> tenantList) {
        super(authorities, username);
        this.tenantList = tenantList;
    }

    public List<TenantInfo> getTenantPath() {
        return tenantList;
    }
    
    public void setTenantPath(List<TenantInfo> tenantList) {
        this.tenantList = tenantList;
    }

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}
    

}

