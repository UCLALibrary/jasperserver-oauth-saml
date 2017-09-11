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


import com.jaspersoft.jasperserver.api.metadata.user.domain.User;
import com.jaspersoft.jasperserver.api.security.externalAuth.ExternalDataSynchronizerImpl;
import com.jaspersoft.jasperserver.api.security.externalAuth.processors.ProcessorData;
import com.jaspersoft.jasperserver.multipleTenancy.MTWebAuthenticationDetails;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static com.jaspersoft.jasperserver.api.security.externalAuth.processors.ProcessorData.Key.*;


public class OAuthMTExternalDataSynchronizerImpl  extends ExternalDataSynchronizerImpl {
		private static final Logger logger = LogManager.getLogger(OAuthMTExternalDataSynchronizerImpl.class);

		protected void loadExternalUserDetailsToProcessorData(final Authentication auth) {
			final ProcessorData processorData = ProcessorData.getInstance();

			final List<Map<String, Object>> loadedDetails = null;
				Object authDetails = auth.getDetails();
		
		//	if (authDetails instanceof OAuthMTUserDetails) {
				String tenantId = ((User) authDetails).getTenantId();
				logger.debug("is externally defined: " +  ((User) authDetails).isExternallyDefined());
				//set the external auth user detail information in the thread safe processorData variable for use by the user processors/synching process
				processorData.addData(EXTERNAL_AUTH_DETAILS, ((UserDetails) authDetails));
				processorData.addData(EXTERNAL_AUTHORITIES, ((UserDetails) authDetails).getAuthorities());
				processorData.addData(EXTERNAL_JRS_USER_TENANT_ID, tenantId == null || tenantId.trim().length() == 0 ? null : tenantId);
		//	}
			
			
			
		}
	
}
