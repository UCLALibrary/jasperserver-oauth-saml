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

import com.jaspersoft.jasperserver.multipleTenancy.MTUserDetails;

public class  OAuthTenantInfo  implements MTUserDetails.TenantInfo, Serializable {

	    private String id;
	    private String label;
	    private String description;

	    public OAuthTenantInfo() {

	    }

	    OAuthTenantInfo(String id, String label, String description) {
	        this.id = id;
	        this.label = label;
	        this.description = description;
	    }

	    public String getId() {
	        return id;
	    }

	    public void setId(String id) {
	        this.id = id;
	    }

	    public String getLabel() {
	        return label;
	    }

	    public void setLabel(String label) {
	        this.label = label;
	    }

	    public String getDescription() {
	        return description;
	    }

	    public void setDescription(String description) {
	        this.description = description;
	    }
	}

