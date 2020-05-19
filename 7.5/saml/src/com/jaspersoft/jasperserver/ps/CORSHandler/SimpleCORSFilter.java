package com.jaspersoft.jasperserver.ps.CORSHandler;
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
import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class SimpleCORSFilter
  implements Filter
{
  private final static Logger log = LoggerFactory.getLogger( SimpleCORSFilter.class );

  public void doFilter( ServletRequest req, ServletResponse res, FilterChain chain )
    throws IOException, ServletException
  {
    HttpServletResponse response = ( HttpServletResponse ) res;
    log.error( "checking response contents" );
    for ( String theHeader : response.getHeaderNames() )
      log.error( "header " + theHeader + " has value " + response.getHeader( theHeader ) );
    response.setHeader( "Access-Control-Allow-Origin", "*" );
    response.setHeader( "Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE" );
    response.setHeader( "Access-Control-Max-Age", "3600" );
    response.setHeader( "Access-Control-Allow-Headers", "x-requested-with" );
    response.setHeader( "X-Frame-Options", "ALLOW" );
    response.setHeader( "Access-Control-Allow-Credentials", "true" );
    chain.doFilter( req, res );
  }

  public void init( FilterConfig filterConfig )
  {
  }

  public void destroy()
  {
  }

}
