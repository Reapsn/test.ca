package test.ca.cipher;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CipherUtils {
	
	public static byte[] PASSWD = "9588028820109132570743325311898426347857298773549468758875018579537757772163084478873699447306034466200616411960574122434059469100235892702736860872901247123456".getBytes();
	
	/**
	 * 加密
	 * 
	 * @param datasource
	 *            byte[]
	 * @param password
	 *            String
	 * @return byte[]
	 * @throws Exception 
	 */
	public static byte[] encrypt(byte[] datasource) throws Exception {
	
		DESKeySpec desKey = new DESKeySpec(PASSWD);
		// 创建一个密匙工厂，然后用它把DESKeySpec转换成
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
		SecretKey securekey = keyFactory.generateSecret(desKey);
		// Cipher对象实际完成加密操作
		Cipher cipher = Cipher.getInstance("DES");
		// 用密匙初始化Cipher对象
		cipher.init(Cipher.ENCRYPT_MODE, securekey,  new SecureRandom());
		// 现在，获取数据并加密
		// 正式执行加密操作
		return cipher.doFinal(datasource);

	}
	
	/**
	 * 解密
	 * 
	 * @param datasource
	 *            byte[]
	 * @param password
	 *            String
	 * @return byte[]
	 * @throws Exception 
	 */
	public static byte[] decrypt(byte[] encryptedData) throws Exception {
		DESKeySpec desKey = new DESKeySpec(PASSWD);
		// 创建一个密匙工厂，然后用它把DESKeySpec转换成
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
		SecretKey securekey = keyFactory.generateSecret(desKey);
		// Cipher对象实际完成加密操作
		Cipher cipher = Cipher.getInstance("DES");
		// 用密匙初始化Cipher对象
		cipher.init(Cipher.DECRYPT_MODE, securekey, new SecureRandom());
		// 现在，获取数据并加密
		// 正式执行解操作
		return cipher.doFinal(encryptedData);

	}
	
	public static boolean keyTest(PublicKey pubKey, PrivateKey priKey,
			String data) throws Exception {

		Cipher cipher = Cipher.getInstance("RSA", new BouncyCastleProvider());
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);

		System.out.println("【密钥对测试】");
		System.out.println("明文 " + data);
		byte[] encrptedData = cipher.doFinal(data.getBytes());
		System.out.println("密文 " + new String(encrptedData));

		cipher.init(Cipher.DECRYPT_MODE, priKey);
		String strDecryptedData = new String(cipher.doFinal(encrptedData));
		System.out.println("解密 " + strDecryptedData);

		if (strDecryptedData.equals(data)) {
			System.out.println("密钥对可用。");
			return true;
		} else {
			System.out.println("密钥对不可用。");
			return false;
		}
	}
}
