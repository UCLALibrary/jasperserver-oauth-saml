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

import javax.sql.DataSource;

import org.springframework.security.authentication.AuthenticationServiceException;




import com.jaspersoft.jasperserver.api.security.externalAuth.ExternalUserDetails;
import com.jaspersoft.jasperserver.api.security.externalAuth.ExternalUserDetailsService;
//interface for sessiondata validation
public interface OAuthAccessTokenValidatorInterface {
	
    public String validate(final Object ssoToken) throws AuthenticationServiceException ;

}
