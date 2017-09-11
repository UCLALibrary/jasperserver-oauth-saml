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
package org.springframework.security.saml;

import org.opensaml.common.SAMLException;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.GenericFilterBean;


import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Class initializes SAML WebSSO profile from the SP side. AuthnRequest is sent to the default IDP
 * with default binding.
 * <p>
 * There are two ways the entry point can get invoked. Either user accesses a URL configured to require
 * some degree of authentication and throws AuhenticationEception which is handled and invokes the entry point.
 * <p>
 * The other way is direct invocation of the entry point by accessing the DEFAULT_FILTER_URL. In this way user
 * can be forwarded to IDP after clicking for example login button.
 *
 * @author Vladimir Sch�fer
 */
public class SAMLEntryPoint extends GenericFilterBean implements AuthenticationEntryPoint {

    /**
     * In case this property is set to not null value the user will be redirected to this URL for selection
     * of IDP to use for login. In case it is null user will be redirected to the default IDP.
     */
    private String idpSelectionPath;

    private WebSSOProfile webSSOprofile;
    private MetadataManager metadata;

    /**
     * Default name of path suffix which will invoke this filter.
     */
    private static final String DEFAUL_FILTER_URL = "/saml/login";

    /**
     * Name of parameter of HttpRequest telling entry point that the login should use specified idp.
     */
    protected static final String IDP_PARAMETER = "idp";

    /**
     * User configured path which overrides the default value.
     */
    private String filterSuffix;

    /**
     * Default constructor
     *
     * @param webSSOprofile initialized web SSO profile
     */
    public SAMLEntryPoint(WebSSOProfile webSSOprofile) {
        this.webSSOprofile = webSSOprofile;
    }

    /**
     * The filter will be used in case the URL of the request ends with DEFAULT_FILTER_URL.
     *
     * @param request request used to determine whether to enable this filter
     * @return true if this filter should be used
     */
    protected boolean processFilter(HttpServletRequest request) {
        if (filterSuffix != null) {
            return (request.getRequestURI().endsWith(filterSuffix));
        } else {
            return (request.getRequestURI().endsWith(DEFAUL_FILTER_URL));
        }
    }

  
   

    /**
     * @param request request
     * @return true if this HttpRequest should be directly forwarded to the IDP without selection of IDP.
     */
    private boolean isLoginRequest(HttpServletRequest request) {
        return request.getParameter("login") != null;
    }

    /**
     * Loads the IDP_PARAMETER from the request and if it is not null verifies whether IDP with this value is valid
     * IDP in our circle of trust. If it is null or the IDP is not configured then the default IDP is returned.
     *
     * @param request request
     * @return null if idp is not set or invalid, name of IDP otherwise
     * @throws MetadataProviderException in case no IDP is configured
     */
    protected String getIDP(HttpServletRequest request) throws MetadataProviderException {
        String s = request.getParameter(IDP_PARAMETER);
        if (s != null) {
            for (String idp : metadata.getIDPEntityNames()) {
                if (idp.equals(s)) {
                    return idp;
                }
            }
        }
        return metadata.getDefaultIDP();
    }

    public void setMetadata(MetadataManager metadata) {
        this.metadata = metadata;
    }

    /**
     * Null if not set otherwise path used for requestDispatcher where user will be redirected for IDP
     * selection.
     *
     * @return null or path
     */
    public String getIdpSelectionPath() {
        return idpSelectionPath;
    }

    public String getFilterSuffix() {
        return filterSuffix;
    }

    public void setFilterSuffix(String filterSuffix) {
        this.filterSuffix = filterSuffix;
    }

    /**
     * Sets path where request dispatcher will send user for IDP selection. In case it is null the default
     * server will always be used.
     *
     * @param idpSelectionPath selection path
     */
    public void setIdpSelectionPath(String idpSelectionPath) {
        this.idpSelectionPath = idpSelectionPath;
    }

	public void commence(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			AuthenticationException arg2) throws IOException, ServletException {
		 try {
	            HttpServletRequest request = (HttpServletRequest) servletRequest;
	            String idp = getIDP((HttpServletRequest) servletRequest);
	            if (idpSelectionPath != null && !isLoginRequest(request)) {
	                request.getRequestDispatcher(idpSelectionPath).include(servletRequest, servletResponse);
	            } else {
	                webSSOprofile.initializeSSO(idp, (HttpServletRequest) servletRequest, (HttpServletResponse) servletResponse);
	            }
	        } catch (SAMLException e1) {
	            throw new ServletException("Error sending assertion", e1);
	        } catch (MetadataProviderException e1) {
	            throw new ServletException("Error sending assertion", e1);
	        } catch (MessageEncodingException e1) {
	            throw new ServletException("Error sending assertion", e1);
	        }
		
	}

	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {
		 if (processFilter((HttpServletRequest)request)) {
	            commence((HttpServletRequest)request, (HttpServletResponse)response, null);
	        } else {
	            chain.doFilter(request, response);
	        }
		
	}

  
}
