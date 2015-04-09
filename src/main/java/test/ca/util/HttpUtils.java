package test.ca.util;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

public class HttpUtils {

	public static KeyPair RequestKeyPair(String name, int length, boolean genNewKey) throws Exception {
		String uri = "http://127.0.0.1:8080/kms/getKeyPair";
		
		HttpPost httpPost = new HttpPost(uri);
		httpPost.setHeader("Accept", "text");
		httpPost.setHeader("Connection", "keep-alive");
		
		List<NameValuePair> values = new ArrayList<NameValuePair>();
		values.add(new BasicNameValuePair("name", name));
		values.add(new BasicNameValuePair("length", length + ""));
		values.add(new BasicNameValuePair("gennewkey", genNewKey + ""));

		httpPost.setEntity(new UrlEncodedFormEntity(values, "UTF-8"));  //进行转码
		
		CloseableHttpClient httpClient = HttpClientBuilder.create().build();
		
		try {
			HttpResponse httpResponse = httpClient.execute(httpPost);

			int statusCode = httpResponse.getStatusLine().getStatusCode();  //返回状态码 ，用来进行识别或者判断访问结果
	
			if(statusCode == 200){
				String strKeyPair = EntityUtils.toString(httpResponse.getEntity());
				String[] arrayStrKeyPair = strKeyPair.split(" ");
				String base64StrPrivateKey = arrayStrKeyPair[0];
				String base64StrPublicKey = arrayStrKeyPair[1];
				X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64StrPublicKey));
				PKCS8EncodedKeySpec  privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64StrPrivateKey));
				
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
				PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
				
				KeyPair keyPair = new KeyPair(publicKey, privateKey);
				return keyPair;
			} else {
				throw new Exception(httpResponse.getStatusLine().toString());
			} 
		} finally {
			httpClient.close();
		}
	}
	
}
