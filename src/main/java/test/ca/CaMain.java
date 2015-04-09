package test.ca;

import test.ca.cert.CertUtils;

public class CaMain {

	public static void main(String[] args) throws Exception {
		
		if (CertUtils.getRootCert() == null) {
			CertUtils.genRootCert(CertUtils.ISSUER);
		}
		
		if(args.length > 0) {
			System.out.println("【签名证书】");
			System.out.println(CertUtils.genSignCert(args[0]));
			System.out.println("【加密证书】");
			System.out.println(CertUtils.genCipherCert(args[0]));
		}
	}
	
}
