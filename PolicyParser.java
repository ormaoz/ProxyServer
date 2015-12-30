// 201530722
// 029983111

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;
import java.util.StringTokenizer;

public class PolicyParser {
	private ArrayList<String> linesFromFile;
	private ArrayList<String> blockedSites;
	private ArrayList<String> blockedResources;
	private HashMap<Inet4Address, Integer> blockedIpMask;
	private ArrayList<String> blockedCountries; // *** BONUS *** 
	File policy;

	/**
	 * Constructor
	 */
	public PolicyParser(File policyFile) {
		this.policy = policyFile;
		blockedSites = new ArrayList<String>();
		blockedResources = new ArrayList<String>();
		blockedIpMask = new HashMap<Inet4Address, Integer>();
		linesFromFile = new ArrayList<String>();
		blockedCountries = new ArrayList<String>(); // *** BONUS ***
	}

	/**
	 * This method open a  scanner and start parse the file using processLine()
	 * line by line 
	 * @throws IOException
	 */
	public final void parseLines() throws IOException {
		// Try to open a scanner for the file
		try {
			Scanner scanner = new Scanner(policy);
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
		linesFromFile.add(line);
		
		// Use another Scanner to parse the content of each line
		@SuppressWarnings("resource")
		Scanner lineScanner = new Scanner(line);
		lineScanner.useDelimiter(" ");

		if (lineScanner.hasNext()) {
			
			// We assume that the policy file is correctly structured
			
			String name = lineScanner.next();
			String value;
			lineScanner.useDelimiter("\"");
			// First separate by space and now by quotes
			if (lineScanner.hasNext()) {
				lineScanner.next();
				value = lineScanner.next();
			// If no quotes separate by space again
			} else {
				lineScanner.useDelimiter(" ");
				value = lineScanner.next();
				// Remove ""
				value = value.substring(1, value.length()-1);
			}
		
			if (name.trim().equals("block-site")) {
				blockedSites.add(value.trim());
			} else if (name.trim().equals("block-resource")) {
				blockedResources.add(value.trim());
			} else if (name.trim().equals("block-ip-mask")) {
				StringTokenizer ipMask = new StringTokenizer(value.trim(), "/");
				String ip = ipMask.nextToken();
				Inet4Address ipAdress = null;
				try {
					ipAdress = (Inet4Address) Inet4Address.getByName(ip);
					Integer mask = Integer.parseInt(ipMask.nextToken());
					blockedIpMask.put(ipAdress, mask);
				} catch (UnknownHostException e) {
					System.err.println("Error converting ip string to IP object " + e);
				}
				
			} else if (name.trim().equals("block-country")) {
				blockedCountries.add(value.toLowerCase());
			} else {
				System.out.println("Policy file had another unknown parameter that was not parsed: " + name);
			}
		} else {
			System.out.println("Empty or invalid line in policy file. Unable to process.");
		}
	}

	public void deleteLine(String line) {
		// Open some temp file
		File tempFile = new File("myTempFile.tmp"); // Temp file
		
		// Read all policy file and check if for the line to remove
		BufferedReader reader;
		try {
			reader = new BufferedReader(new FileReader(policy));
			
			BufferedWriter writer = new BufferedWriter(new FileWriter(tempFile));
	
			String currentLine;
	
			while((currentLine = reader.readLine()) != null) {
			    
				// Write all the line to the temp file BUT the deleted line
				if(currentLine.equals(line)) {
			    	continue;
			    }
			    writer.write(currentLine);
			    writer.newLine();
			}
			writer.close();
			reader.close();
		} catch (IOException e) {
			System.err.println("Error in the process of deletign from policy file " + e);
		}
		
		// Open new reader and writer and now write the updated content back to the original file
		BufferedReader readerBack;
		try {
			readerBack = new BufferedReader(new FileReader(tempFile));
			
			BufferedWriter writerBack = new BufferedWriter(new FileWriter(policy));
	
			String currentLineBack;
	
			while((currentLineBack = readerBack.readLine()) != null) {
				writerBack.write(currentLineBack);
				writerBack.newLine();
			}
			writerBack.close();
			readerBack.close();
			// Delete temp file
			tempFile.delete();

			this.parseLines();
		} catch (IOException e) {
			System.err.println("Error in the process of deletign from policy file " + e);
		}
		
	}
	
	public void addLine(String newPolicy) {
		// Open some temp file
		File tempFile = new File("myTempFile.tmp"); // Temp file
		
		// Read all policy file and and write it to temp file
		BufferedReader reader;
		try {
			reader = new BufferedReader(new FileReader(policy));
			
			BufferedWriter writer = new BufferedWriter(new FileWriter(tempFile));
	
			String currentLine;
	
			while((currentLine = reader.readLine()) != null) {
			    writer.write(currentLine);
			    writer.newLine();
			}
			// After all, add the new line
			writer.write(newPolicy);
			writer.newLine();
			writer.close();
			reader.close();
		} catch (IOException e) {
			System.err.println("Error in the process of deletign from policy file " + e);
		}
		
		// Open new reader and writer and now write the updated content back to the original file
		BufferedReader readerBack;
		try {
			readerBack = new BufferedReader(new FileReader(tempFile));
			
			BufferedWriter writerBack = new BufferedWriter(new FileWriter(policy));
	
			String currentLineBack;
	
			while((currentLineBack = readerBack.readLine()) != null) {
				writerBack.write(currentLineBack);
				writerBack.newLine();
			}
			writerBack.close();
			readerBack.close();
			// Delete temp file
			tempFile.delete();

			this.parseLines();
		} catch (IOException e) {
			System.err.println("Error in the process of deletign from policy file " + e);
		}
	}
	
	public void modifyLine(String oldPolicy, String newPolicy) {
		this.addLine(newPolicy);
		this.deleteLine(oldPolicy);
	}
	public ArrayList<String> getAllFileContent() {
		return linesFromFile;
	}
	
	public ArrayList<String> getBlockedSites() {
		return blockedSites;
	}

	public ArrayList<String> getBlockedResources() {
		return blockedResources;
	}

	public HashMap<Inet4Address, Integer> getBlockedIpMask() {
		return blockedIpMask;
	}
	public ArrayList<String> getBlockedCountries() {
		return blockedCountries;
	}

}
