package test.ca.util;

import java.io.File;
import java.net.URL;

public class PathUtils {
	
	public static URL findClassPathUri(Class<?> cls) {
		// Get current class resource URL
		ClassLoader loader = cls.getClassLoader();
		String className = cls.getCanonicalName();
		className = className.replace('.', '/') + ".class";
		return loader.getResource(className);
	}

	/**
	 * Using ClassLoader.getResources() to find the plugin's home directory.
	 */
	public static String findHomePath() {

		// 1. Get the plugin home path by strip the class url
		// The url seems like as: /E:/plugins/koal.sa.client.dev.info/classes/koal/sa/.../PluginImpl.class
		String classPathString = findClassPathUri(PathUtils.class).getFile();
		
		String homePath = classPathString;
		
		// 2. process url prefix
		if (homePath.startsWith("file:")) {
			homePath = homePath.substring(5);
		}
		
		// 3. Trim the first slash(/) character on Windows OS.
		if (File.separatorChar == '\\') {
			homePath = homePath.substring(1);
		}
		
		// 4. cut class name in path
		String className = PathUtils.class.getCanonicalName();
		int classNameLengthInPath = className.length() + ".class".length();
		homePath = homePath.substring(0, homePath.length() - classNameLengthInPath);

		// 5. process jar! file
		if (homePath.toLowerCase().contains(".jar!")) {
			homePath = new File(homePath).getParent();
		}

		// 6. Plugin library always in 'lib' or 'classes' directory, so the parent path is the real plugin home path.
		homePath = new File(homePath).getParent();
		
		return homePath;
	}
	
}
