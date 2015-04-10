package test.ca;

import java.util.Scanner;

import test.ca.cert.CertUtils;

public class CaMain {

	public static void main(String[] args) throws Exception {
		
		if (CertUtils.getRootCert() == null) {
			CertUtils.genRootCert(CertUtils.ISSUER);
		}
		
		Scanner scanner = new Scanner(System.in);
		System.out.print("请输入 name:");
		String input = scanner.next();
		while(!"q!".equals(input)) {
			System.out.println("【签名证书】");
			System.out.println(CertUtils.genSignCert(input));
			System.out.println("【加密证书】");
			System.out.println(CertUtils.genCipherCert(input));
			
			System.out.print("请输入 name:");
			input = scanner.next();
		}
		scanner.close();
	}
	
}
