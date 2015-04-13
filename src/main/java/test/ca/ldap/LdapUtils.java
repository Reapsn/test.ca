package test.ca.ldap;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import test.ca.util.StringUtils;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException; 
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;

public class LdapUtils {

	public static String LDAP ="ldap";
	public static String HOST = "192.168.40.82";
	public static int PORT = 389;
	public static String BASE_DIR = "dc=test,dc=net";
	public static String ADMIN_COUNT_DN = "cn=admin," +BASE_DIR;
	public static String ADMIN_PASSWORD = "1234";
	public static String CERT_PATH = "ou=Certificates," + BASE_DIR;
	
	public static LDAPConnection getLdapConnection() throws LDAPException {
		LDAPConnection conn = new LDAPConnection(HOST, PORT, ADMIN_COUNT_DN, ADMIN_PASSWORD);
		return conn;
	}
	
	public static List<SearchResultEntry> queryLdap(String searchScope,
			String filter) throws LDAPException {
		LDAPConnection connection = null;
		try {
			connection = getLdapConnection();
			SearchRequest searchRequest = new SearchRequest(searchScope,
					SearchScope.SUB, "(" + filter + ")");
			SearchResult searchResult = connection.search(searchRequest);
			return searchResult.getSearchEntries();
		} finally {
			try {
				connection.close();
			} catch (Exception e) {
				; // quitClose
			}
		}
	}

	public static LDAPResult addOneNode(final String dn,
			final Collection<Attribute> attributes) throws LDAPException {
		LDAPConnection connection = null;
		try {
			connection = getLdapConnection();
			LDAPResult result = connection.add(dn, attributes);
			return result;
		} finally {
			try {
				connection.close();
			} catch (Exception e) {
				; // quitClose
			}
		}
	}
	
	public static LDAPResult addOrganizationalUnit(String baseScope,
			String groupName) throws LDAPException {
		String dn = "ou=" + groupName + "," + baseScope;
		List<Attribute> attributes = new ArrayList<Attribute>();
		attributes.add(new Attribute("ou", groupName));
		attributes.add(new Attribute("objectClass", "organizationalUnit"));
		return addOneNode(dn, attributes);
	}
	
	public static LDAPResult addOneCert(Certificate certificate)
			throws Exception {
		X509Certificate cert = (X509Certificate) certificate;
		String certDn = cert.getSubjectDN().getName();
		String certCn = StringUtils.getValueFromDn(certDn, "CN");
		String dn = "cn=" + certCn + "," + CERT_PATH;
		List<Attribute> attributes = new ArrayList<Attribute>();
		attributes.add(new Attribute("cn", certCn));
		attributes.add(new Attribute("sn", cert.getSerialNumber() + ""));
		attributes.add(new Attribute("userCertificate;binary", cert.getEncoded()));
		attributes.add(new Attribute("objectClass", "top", "person","pkiUser"));
		return addOneNode(dn, attributes);
	}
}
