// 201530722
// 029983111

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Scanner;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class ConfigParser {
	private int port;
	private String root;
	private String defaultPage;
	private int maxThreads;
	private String logPath;
	private String exListPath;
	File config;

	/**
	 * Constructor
	 */
	public ConfigParser(File configFile) {
		this.config = configFile;
	}

	/**
	 * This method open a  scanner and start parse the file using processLine()
	 * line by line 
	 * @throws IOException
	 */
	public final void parseLines() throws IOException {
		// Try to open a scanner for the file
		try {
			Scanner scanner = new Scanner(config);
			// As long as there are more lines to read, read next line
			while (scanner.hasNextLine()) {
				processLine(scanner.nextLine());
			}
			scanner.close();
		// If failed reading the file, print error.
		} catch (Exception e) {
			System.out.println("Error with reading file: " + e);
		}
	}

	/**
	 * This method receive a string line and parse it to name and value and 
	 * saves the parameters accordingly 
	 * @param line
	 */
	private void processLine(String line) {
		// Use another Scanner to parse the content of each line
		@SuppressWarnings("resource")
		Scanner lineScanner = new Scanner(line);
		lineScanner.useDelimiter("=");
		if (lineScanner.hasNext()) {
			
			// We assume that the config file is correctly structured
			
			String name = lineScanner.next();
			String value = lineScanner.next();
	
			if (name.trim().equals("port")) {
				this.port = Integer.parseInt(value.trim());
			} else if (name.trim().equals("root")) {
				this.root = value.trim();
			} else if (name.trim().equals("defaultPage")) {
				this.defaultPage = value.trim();
			} else if (name.trim().equals("maxThreads")) {
				this.maxThreads = Integer.parseInt(value.trim());
			} else if (name.trim().equals("logPath")) {
				this.logPath = value.trim();
			} else if (name.trim().equals("CountryExtensionPath")) {
				this.exListPath = value.trim();
			} else {
				System.out.println("Config file had another unknown parameter that was not parsed");
			}
		} else {
			System.out.println("Empty or invalid line in config file. Unable to process.");
		}
	}

	public int getPort() {
		return port;
	}

	public String getRoot() {
		return root;
	}

	public String getDefaultPage() {
		return defaultPage;
	}
	
	public String getLogPath() {
		return logPath;
	}

	public int getMaxThreads() {
		return maxThreads;
	}

	public String getExListPath() {
		return exListPath;
	}
}
