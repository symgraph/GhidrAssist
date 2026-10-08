package ghidrassist;

import java.io.File;

import ghidra.framework.Application;

public class GAUtils {
	public enum OperatingSystem {
	    WINDOWS, MAC, LINUX, UNKNOWN;
	
	    public static OperatingSystem detect() {
	        String os = System.getProperty("os.name").toLowerCase();
	        if (os.contains("win")) {
	            return WINDOWS;
	        } else if (os.contains("mac")) {
	            return MAC;
	        } else if (os.contains("nix") || os.contains("nux") || os.contains("aix")) {
	            return LINUX;
	        } else {
	            return UNKNOWN;
	        }
	    }
	}
	
	/**
	 * Directory for GhidrAssist's own files (Lucene index, databases). It lives in
	 * Ghidra's user settings directory, so portable Ghidra installs keep everything
	 * in one place and nothing is written to the home directory.
	 */
	public static File getDataDirectory() {
	    File dir = new File(Application.getUserSettingsDirectory(), "GhidrAssist");
	    dir.mkdirs();
	    return dir;
	}

	/** Default location of a GhidrAssist data file when no preference overrides it. */
	public static String getDefaultDataPath(String fileName) {
	    return new File(getDataDirectory(), fileName).getPath();
	}

	public static String getDefaultLucenePath(OperatingSystem os) {
	    return new File(getDataDirectory(), "LuceneIndex").getPath();
	}

}