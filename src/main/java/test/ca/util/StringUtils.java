package test.ca.util;

public class StringUtils {
	
	public static String getValueFromDn(String dn, String name) {
		if(dn == null) {
			throw new IllegalArgumentException("dn must not be null");
		}
		String value = null;
		String[] nameValues = dn.replaceAll("[\\s]", "").split(",");
		for (int i = 0; i < nameValues.length; i++) {
			String[] nameValue = nameValues[i].split("=");
			if (nameValue[0].equals(name)) {
				value = nameValue[1];
				break;
			}
		}
		return value;
	}
}
