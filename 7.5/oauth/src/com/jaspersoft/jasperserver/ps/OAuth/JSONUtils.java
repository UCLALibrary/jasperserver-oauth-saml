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

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.json.JSONException;
import org.json.JSONObject;

public class JSONUtils {
	public static Map<String,String> getJSONasMap(JSONObject js){
		 Map<String,String> out = new HashMap<String, String>();

		    try {
				parse(js,out);
				return out;
			} catch (JSONException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		    return null;
	}
	private static Map<String,String> parse(JSONObject json , Map<String,String> out) throws JSONException{
	    Iterator<String> keys = json.keys();
	    while(keys.hasNext()){
	        String key = keys.next();
	        String val = null;
	        try{
	             JSONObject value = json.getJSONObject(key);
	             parse(value,out);
	        }catch(Exception e){
	            val = json.getString(key);
	        }

	        if(val != null){
	            out.put(key,val);
	        }
	    }
	    return out;
	}
	

public static String getMapEntry(Map<String,String> map, String searchstring){

for (Map.Entry<String, String> entry : map.entrySet())
{
	if(entry.getKey().toLowerCase().contains(searchstring.toLowerCase())){
		return entry.getValue();
	}
	
}
return null;

}


public static JSONObject getClaimsInformationFromAccessTokenAsJsonNode(String tokenString) {
    String[] pieces = splitTokenString(tokenString);
    String jwtHeaderSegment = pieces[0];
    String jwtPayloadSegment = pieces[1];
    byte[] signature = Base64.decodeBase64(pieces[2]);
   
		JSONObject myobj;
		try {
			myobj = new JSONObject(new String(Base64.decodeBase64(jwtPayloadSegment)));
			return myobj;
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	return null;
   
   
  }
private static String[] splitTokenString(String tokenString) {
    String[] pieces = tokenString.split("\\.");
    if (pieces.length != 3) {
      throw new IllegalStateException("Expected JWT to have 3 segments separated by '" +
          "." + "', but it has " + pieces.length + " segments");
    }
    return pieces;
  }
}
