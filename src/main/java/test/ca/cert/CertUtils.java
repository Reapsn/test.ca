package test.ca.cert;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import test.ca.cipher.CipherUtils;
import test.ca.util.HttpUtils;
import test.ca.util.PathUtils;

public class CertUtils {

	public static final String CERT_STORE;
	public static final String PFX_ROOT_CERT;
	public static final String ROOT_CERT;
	public static final String ISSUER = "C=CN,ST=SH,L=SH,O=Koal,OU=Koal,CN=TestCA";
	public static final String BASE_SUBJECT = "C=CN,ST=SH,L=SH,O=Koal,OU=Koal,CN=";
	public static final char[] KEY_STORE_PASSWORD = "".toCharArray();
	public static final String ROOT_ALIAS = "root";
	public static final String SIGNATURE_ALGORITHM = "SHA256WithRSA";
	public static final String PKCS12= "PKCS12";
	public static final String SIGN_PFX = ".sign.pfx";
	public static final String CIPHER_PFX = ".cipher.pfx";
	
	static {
		CERT_STORE = PathUtils.findHomePath() + File.separatorChar + "store";
		File store = new File(CERT_STORE);
		if (!store.exists()) {
			store.mkdir();
		}
		PFX_ROOT_CERT = CERT_STORE + File.separatorChar + "root.pfx";
		ROOT_CERT = CERT_STORE + File.separatorChar + "root.cer";
	}
	
	public static Certificate genSignCert(String name) throws Exception {
		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024);
		
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		// 公钥  
        PublicKey pubKey = keyPair.getPublic();  
        // 私钥  
        PrivateKey priKey = keyPair.getPrivate(); 
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();  
        // 设置序列号  
        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));  
        // 设置颁发者  
        certGen.setIssuerDN(new X500Principal(ISSUER));  
        // 设置有效期  
        certGen.setNotBefore(new Date());  
        certGen.setNotAfter(DateUtils.addYears(new Date(), 1));  
        // 设置使用者  
        certGen.setSubjectDN(new X500Principal(BASE_SUBJECT + name));  
        // 公钥  
        certGen.setPublicKey(pubKey);
        // 签名算法  
        certGen.setSignatureAlgorithm(SIGNATURE_ALGORITHM); 
        Certificate certificate = certGen.generate(getRootPrivateKey());
		
        // 保存证书
        String pfxFile = CERT_STORE + File.separatorChar + name + SIGN_PFX;
        FileOutputStream output = new FileOutputStream(pfxFile);
		KeyStore outputKeyStore = KeyStore.getInstance(PKCS12);
		outputKeyStore.load(null, KEY_STORE_PASSWORD);
		outputKeyStore.setKeyEntry(name, priKey, KEY_STORE_PASSWORD,
				new Certificate[] { certificate });
		outputKeyStore.store(output, KEY_STORE_PASSWORD);
        output.close();
        
		return certificate;
	}
	
public static Certificate genCipherCert(String name) throws Exception {
		
		KeyPair keyPair = HttpUtils.RequestKeyPair(name, 1024, false);
		
		// 公钥  
        PublicKey pubKey = keyPair.getPublic();  
        // 私钥  
        PrivateKey priKey = keyPair.getPrivate();
        if (!CipherUtils.keyTest(pubKey, priKey, name)) {
        	throw new Exception("密钥对无效。");
        }
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();  
        // 设置序列号  
        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));  
        // 设置颁发者  
        certGen.setIssuerDN(new X500Principal(ISSUER));  
        // 设置有效期  
        certGen.setNotBefore(new Date());  
        certGen.setNotAfter(DateUtils.addYears(new Date(), 1));  
        // 设置使用者  
        certGen.setSubjectDN(new X500Principal(BASE_SUBJECT + name));  
        // 公钥  
        certGen.setPublicKey(pubKey);
        // 签名算法  
        certGen.setSignatureAlgorithm(SIGNATURE_ALGORITHM); 
        Certificate certificate = certGen.generate(getRootPrivateKey());
		
        // 保存证书
        String pfxFile = CERT_STORE + File.separatorChar + name + CIPHER_PFX;
        FileOutputStream output = new FileOutputStream(pfxFile);
		KeyStore outputKeyStore = KeyStore.getInstance(PKCS12);
		outputKeyStore.load(null, KEY_STORE_PASSWORD);
		outputKeyStore.setKeyEntry(name, priKey, KEY_STORE_PASSWORD,
				new Certificate[] { certificate });
		outputKeyStore.store(output, KEY_STORE_PASSWORD);
        output.close();
        
		return certificate;
	}
	
	public static void genRootCert(String issuer) throws Exception {
		
		KeyPair keyPair = HttpUtils.RequestKeyPair("root", 2048, false);
        // 公钥  
        PublicKey pubKey = keyPair.getPublic();  
        // 私钥  
        PrivateKey priKey = keyPair.getPrivate();  
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();  
        // 设置序列号  
        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));  
        // 设置颁发者  
        certGen.setIssuerDN(new X500Principal(issuer));  
        // 设置有效期  
        certGen.setNotBefore(new Date());  
        certGen.setNotAfter(DateUtils.addYears(new Date(), 10));  
        // 设置使用者  
        certGen.setSubjectDN(new X500Principal(issuer));  
        // 公钥  
        certGen.setPublicKey(pubKey);  
        // 签名算法  
        certGen.setSignatureAlgorithm(SIGNATURE_ALGORITHM); 
        Certificate rootCert = certGen.generate(priKey);
		
        // 保存根证书
        FileOutputStream output = new FileOutputStream(PFX_ROOT_CERT);
		KeyStore outputKeyStore = KeyStore.getInstance(PKCS12);
		outputKeyStore.load(null, KEY_STORE_PASSWORD);
		outputKeyStore.setKeyEntry(ROOT_ALIAS, priKey, KEY_STORE_PASSWORD,
				new Certificate[] { rootCert });
		outputKeyStore.store(output, KEY_STORE_PASSWORD);
        output.close();

        FileUtils.writeByteArrayToFile(new File(ROOT_CERT), rootCert.getEncoded());
	}
	
	public static Certificate getRootCert() {
		try {
			KeyStore inputKeyStore = KeyStore.getInstance(PKCS12);
			FileInputStream fis = new FileInputStream(PFX_ROOT_CERT);
			inputKeyStore.load(fis, KEY_STORE_PASSWORD);
			fis.close();

			Certificate rootCert = inputKeyStore.getCertificate(ROOT_ALIAS);

			return rootCert;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static PrivateKey getRootPrivateKey() {
		PrivateKey privateKey = null;
		try {

			KeyStore inputKeyStore = KeyStore.getInstance(PKCS12);
			FileInputStream fis = new FileInputStream(PFX_ROOT_CERT);
			inputKeyStore.load(fis, KEY_STORE_PASSWORD);
			fis.close();

			privateKey = (PrivateKey) inputKeyStore.getKey(ROOT_ALIAS, KEY_STORE_PASSWORD);

		} catch (Exception e) {
			// e.printStackTrace();
			// ignore
		}
		return privateKey;
	}
	
	public static Certificate readSignCert(String name) throws Exception {
		KeyStore inputKeyStore = KeyStore.getInstance(PKCS12);
		FileInputStream fis = new FileInputStream(CERT_STORE
				+ File.separatorChar + name + SIGN_PFX);
		inputKeyStore.load(fis, KEY_STORE_PASSWORD);
		fis.close();

		Certificate cert = inputKeyStore.getCertificate(name);

		return cert;
	}
	
	public static Certificate readCipherCert(String name) throws Exception {
		KeyStore inputKeyStore = KeyStore.getInstance(PKCS12);
		FileInputStream fis = new FileInputStream(CERT_STORE
				+ File.separatorChar + name + CIPHER_PFX);
		inputKeyStore.load(fis, KEY_STORE_PASSWORD);
		fis.close();

		Certificate cert = inputKeyStore.getCertificate(name);
		
		return cert;
	}
}
