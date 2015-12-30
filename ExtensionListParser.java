// 201530722
// 029983111


import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Scanner;

public class ExtensionListParser {
	HashMap<String, String> extensionToCountryList;
	File exList;

	/**
	 * Constructor
	 */
	public ExtensionListParser(File extensionFile) {
		this.exList = extensionFile;
		extensionToCountryList = new HashMap<String, String>();
	}

	/**
	 * This method open a  scanner and start parse the file using processLine()
	 * line by line 
	 * @throws IOException
	 */
	public final void parseLines() throws IOException {
		// Try to open a scanner for the file
		try {
			Scanner scanner = new Scanner(exList);
			
			// As long as there are more lines to read, read next line
			while (scanner.hasNextLine()) {
				processLine(scanner.nextLine());
			}
			scanner.close();
		// If failed reading the file, print error.
		} catch (Exception e) {
			System.err.println("Error with reading file extension: " + e);
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
		lineScanner.useDelimiter("\t");
		if (lineScanner.hasNext()) {

			// We assume that the extension file is correctly structured
			String extension = lineScanner.next().toLowerCase();
			String country = lineScanner.next().toLowerCase();
			this.extensionToCountryList.put(country, extension);
		} else {
			System.out.println("Empty or invalid line in extension file. Unable to process.");
		}
	}

	public String getExtension(String country) {
		return extensionToCountryList.get(country);
	}
}
