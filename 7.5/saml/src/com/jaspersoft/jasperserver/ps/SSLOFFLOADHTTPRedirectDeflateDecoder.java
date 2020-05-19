package com.jaspersoft.jasperserver.ps;

import javax.servlet.http.HttpServletRequest;

import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.parse.ParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SSLOFFLOADHTTPRedirectDeflateDecoder extends HTTPRedirectDeflateDecoder
{
	
	
	public SSLOFFLOADHTTPRedirectDeflateDecoder() {
	    super();
	}
	
	public SSLOFFLOADHTTPRedirectDeflateDecoder(ParserPool pool) {
	    super(pool);
	}

	private final Logger log = LoggerFactory.getLogger(SSLOFFLOADHTTPRedirectDeflateDecoder.class);
	
	@Override
	 protected String getActualReceiverEndpointURI(SAMLMessageContext messageContext) throws MessageDecodingException {
	        InTransport inTransport = messageContext.getInboundMessageTransport();
	        if (! (inTransport instanceof HttpServletRequestAdapter)) {
	            log.error("Message context InTransport instance was an unsupported type: {}", 
	                    inTransport.getClass().getName());
	            throw new MessageDecodingException("Message context InTransport instance was an unsupported type");
	        }
	        HttpServletRequest httpRequest = ((HttpServletRequestAdapter)inTransport).getWrappedRequest();
	       
	        String urlBuilder = httpRequest.getRequestURL().toString();
	        //MOD URL HERE
	        urlBuilder = urlBuilder.replaceFirst("http", "https");
	        
	        return urlBuilder.toString();
	}
	
}