package test.ca;

import java.security.cert.Certificate;
import java.util.Scanner;

import test.ca.cert.CertUtils;
import test.ca.ldap.LdapUtils;

public class CaMain {

	public static void main(String[] args) throws Exception {
		
		if (CertUtils.getRootCert() == null) {
			CertUtils.genRootCert(CertUtils.ISSUER);			
		}
//		LdapUtils.addOrganizationalUnit(LdapUtils.BASE_DIR, "Certificates");
		
		Scanner scanner = new Scanner(System.in);
		System.out.print("请输入 name:");
		String input = scanner.next();
		while(!"q!".equals(input)) {
			System.out.println("【签名证书】");
			System.out.println(CertUtils.genSignCert(input));
			System.out.println("【加密证书】");
			System.out.println(CertUtils.genCipherCert(input));
			
			try {
				Certificate certificate = CertUtils.readCipherCert(input);
				LdapUtils.addOneCert(certificate);
				System.out.println(input + "的签名证书已经发布到LDAP。");
			} catch (Exception e) {
				System.out.println(input + "的签名证书发布失败。");
				e.printStackTrace();
			}
			
			System.out.print("请输入 name:");
			input = scanner.next();
		}
		scanner.close();
		
	}
	
}
