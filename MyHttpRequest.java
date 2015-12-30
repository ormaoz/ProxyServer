// 201530722
// 029983111

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.sql.Time;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.StringTokenizer;

final class MyHttpRequest implements Runnable {

	private class Err {
		String msg;
		String file;

		public Err(String msg, String file) {
			this.msg = msg;
			this.file = file;
		}
	}

	final static String CRLF = "\r\n";
	final static int CHUNK = 1024;
	final static String CHUNKHEX = Integer.toHexString(CHUNK);
	final static String DFLTVERS = "HTTP/1.0";

	Map<Integer, Err> err;
	Socket socket;
	String root;
	String defaultPage;
	String logPath;
	File config;
	String hostName;
	String policyPath;
	File logFile;
	File policyFile;
	String exListPath;
	File exListFile;

	/**
	 * Constructor
	 * 
	 * @param socket
	 * @param policyPath 
	 * @throws Exception
	 */
	public MyHttpRequest(Socket socket, String policyPath) {
		err = new HashMap<Integer, Err>();
		err.put(403, new Err("403 Access Denied", "403.html"));
		err.put(404, new Err("404 Not Found", "404.html"));
		err.put(501, new Err("501 Not Implemented", "501.html"));
		err.put(400, new Err("400 Bad Request", "400.html"));
		err.put(500, new Err("500 Internal Server Error", "500.html"));

		this.socket = socket;
		File configFile = new File("config.ini");
		
		// Parse the root and default page from config.ini
		ConfigParser parser = new ConfigParser(configFile);
		try {
			parser.parseLines();
		} catch (IOException e) {
			System.err.println("Failed in prasing config file " + e);
		}
		this.root = parser.getRoot();
		this.defaultPage = parser.getDefaultPage();
		this.logPath = parser.getLogPath();
		this.policyPath = policyPath;
		this.logFile = new File(logPath);
		this.policyFile = new File(policyPath);
		this.exListPath = parser.getExListPath();
		this.exListFile = new File (exListPath);

	}

	// Implement the run() method of the Runnable interface.
	public void run() {
		try {
			processRequest();
		} catch (Exception e) {
			if (!this.socket.isClosed()) {
				try {
					DataOutputStream os = new DataOutputStream(socket.getOutputStream());
					sendErrorResponse(os, err.get(500));
				} catch (Exception e2) {
					System.out.println(e2);
				}
			}
		}
	}

	/**
	 * This method opens gets the input stream from the socket, parse it to the
	 * different parameters and build the response accordingly using
	 * responseBuilder()
	 * 
	 * @throws Exception - if write to stream failed
	 */
	private void processRequest() throws Exception {

		InputStream instream = socket.getInputStream();
		DataOutputStream os = new DataOutputStream(socket.getOutputStream());
		BufferedReader br = new BufferedReader(new InputStreamReader(instream));

		// Get the request line of the HTTP request message.
		String requestLine = br.readLine();

		if (requestLine == null) {
			System.out.println();
			sendErrorResponse(os, err.get(400));
			br.close();
			return;
		}
		// Parse the request line
		StringTokenizer tokens = new StringTokenizer(requestLine);
		String method = null;
		String fileName = null;
		String version = null;
		String originalFullPath = null;
		try {
			// request method type
			method = tokens.nextToken();

			// requested page
			fileName = tokens.nextToken();
			originalFullPath = fileName;
			if (fileName.startsWith("http://")) {
				fileName = fixProxyFileName(fileName);
			}

			// request version
			version = tokens.nextToken();
		} catch (NoSuchElementException e) {
			System.out.println();
			sendErrorResponse(os, err.get(400));
			br.close();
			return;
		}

		// For the trace option:
		StringBuilder trace = new StringBuilder();
		trace.append(method + " " + fileName + " " + version + "\n");

		// Print the HTTP requests arriving to the server
		System.out.println(method + " " + fileName + " " + version);

		// Parse the rest of the request
		Map<String, String> headers = new HashMap<String, String>();
		String name = null;
		String value = null;
		String headerLine = null;

		while ((headerLine = br.readLine()).length() != 0) {

			// print the header to screen
			System.out.println(headerLine);
			trace.append(headerLine + "\n");

			// add the header to hashmap
			int colon = headerLine.indexOf(":");
			if (colon == -1) {
				System.out.println();
				sendErrorResponse(os, err.get(400));
				br.close();
				return;
			}

			name = headerLine.substring(0, colon).trim();
			value = headerLine.substring(colon + 1).trim();
			if (name != null) {
				headers.put(name, value);
			}
		}
		System.out.println();

		// Host header
		hostName = headers.get("Host");

		// Referrer header
		String referer = headers.get("Referer");

		// user-agent header
		String userAgent = headers.get("User-Agent");

		// Check if the request contains the HTTP header “chunked: yes”
		Boolean isChunked = false;
		String val = null;
		if ((val = headers.get("chunked")) != null && val.equals("yes")) {
			isChunked = true;
		}

		// Create a hash map for future parameters
		HashMap<String, String> parametersSeparated = new HashMap<String, String>();

		String newFileName = null;

		// If POST or GET methods, check for parameters and parse them
		if (method.equals("POST") || method.equals("GET")) {

			StringBuilder parameterFromFile = new StringBuilder();

			// Parse parameters from
			if (fileName.contains("?")) {
				StringTokenizer fileAndParams = new StringTokenizer(fileName, "?");
				newFileName = fileAndParams.nextToken();
				parameterFromFile.append(fileAndParams.nextToken());
			}
			paramSeperator(parameterFromFile, parametersSeparated);
		}

		StringBuilder postBody = null;
		// If it's POST method, parse body too
		if (method.equals("POST")) {
			postBody = new StringBuilder();

			// Save the length of the body
			int bodyLength = Integer.parseInt(headers.get("Content-Length"));

			// Save the body to a String
			for (int i = 0; i < bodyLength; i++) {
				postBody.append((char) br.read());
			}
			paramSeperator(postBody, parametersSeparated);
		}

		// Assign name without parameters
		if (newFileName != null) {
			fileName = newFileName;
		}

		// Prevent user from using '..'
		while (fileName.contains("/..")) {
			int beginIndex = fileName.indexOf("/..");
			int endIndex = fileName.length();
			StringBuilder fixedName = new StringBuilder();
			fixedName.append(fileName.substring(0, beginIndex));
			fixedName.append(fileName.substring(beginIndex + 3, endIndex));
			fileName = fixedName.toString();
		}

		// If the request is not aimed toward my server, then it's a request
		// for the proxy and we should send it original host.
		if (!(hostName.contains("localhost") || hostName.contains("127.0.0.1") || hostName.equals("content-proxy"))) {
			String postBodyString = null;
			if (postBody != null) {
				postBodyString = postBody.toString();
			}
			trace.append("\n");
			String fileType = "";
			if (fileName.contains(".")) {
				int i = fileName.lastIndexOf('.');
				if (i > 0) {
					fileType = fileName.substring(i);
				}
			}
			try {

				sendRequestToServer(trace.toString(), postBodyString, 
						os, isChunked, fileType, policyPath, originalFullPath);
			} catch (IOException e) {
				System.err.println("Error in sending request to server " + e);
			}

		// The request is for our server
		} else {

			// In case the call is for log file commands
			if (hostName.equals("content-proxy")) {
				if (fileName.equals("/logs")) {
					Boolean deleteLog = false;
					try {
						if (parametersSeparated.get("delete").equals("DeleteLog")) {
							deleteLog = true;
						}
					} catch (Exception e) {
						// Could not find delete because no one tried to delete
					}
					
					fileName = root + "logs.html";
					PrintWriter writeLogFile = new PrintWriter(fileName);
					String htmlCode = createLogsPage(deleteLog);
					writeLogFile.println(htmlCode);
					writeLogFile.close();
				}
				else if (fileName.equals("/policies")) {
					fileName = root + "editPolicy.html";
					PrintWriter writePolicyFile = new PrintWriter(fileName);
					String htmlCode = createPolicyPage();
					writePolicyFile.println(htmlCode);
					writePolicyFile.close();
				} else if (fileName.equals("/done.html")) { 
					updatePolicyFile(parametersSeparated, os);
					fileName = root + "editPolicy.html";
					PrintWriter writePolicyFile = new PrintWriter(fileName);
					String htmlCode = createPolicyPage();
					writePolicyFile.println(htmlCode);
					writePolicyFile.close();
				} else {
					// Write error to user
					sendErrorResponse(os, err.get(404));
					return;
				}
			}
		
			// Open the requested file.
			File file = new File(fileName);
			FileInputStream fis = null;
			boolean fileExists = true;
			try {
				fis = new FileInputStream(fileName);
			} catch (FileNotFoundException e) {
				fileExists = false;
			}

			// Send the proper response
			try {
				responseBuilder(os, method, fileName, version, file, fileExists, isChunked, fis, trace.toString());
			} catch (Exception e) {
				sendErrorResponse(os, err.get(500));
				br.close();
				return;
			}
			br.close();
		}

		// Close really old connections (100,000 milliseconds old)
		long t = System.currentTimeMillis();
		long end = t + 1000;
		while (System.currentTimeMillis() < end) {
		}
	}

	private void updatePolicyFile(HashMap<String, String> parametersSeparated, DataOutputStream os) {

		String action = parametersSeparated.get("Action");
		String chosenPolicy = parametersSeparated.get("policy_checked");
		String chosenPolicyDecoded = chosenPolicy;
		String category = parametersSeparated.get("category");
		String value = parametersSeparated.get("modifyValue");
		String valueDecoded = value;
		try {
			if (chosenPolicy != null) {
				chosenPolicyDecoded = URLDecoder.decode(chosenPolicy, "UTF-8");
				chosenPolicyDecoded = chosenPolicyDecoded.replace('*', '\"');
			}
			valueDecoded = URLDecoder.decode(value, "UTF-8");
			valueDecoded = valueDecoded.toLowerCase();
		} catch (Exception e) {
			System.out.println("Error in decoding input " + e);
		}
		StringBuilder newBlocked = new StringBuilder();
		newBlocked.append(category);
		newBlocked.append(" ");
		if (!valueDecoded.startsWith("\"")) {
			newBlocked.append("\"" + valueDecoded + "\"");
		} else {
			newBlocked.append(valueDecoded);
		}
		PolicyParser policyParser = new PolicyParser(policyFile);
		if (action.equals("Delete")) {
			policyParser.deleteLine(chosenPolicyDecoded);
		} else if (action.equals("Modify")) {
			policyParser.modifyLine(chosenPolicyDecoded, newBlocked.toString());
		} else if (action.equals("Add")) {
			policyParser.addLine(newBlocked.toString());
		} else {
			sendErrorResponse(os, err.get(500));
			return;
		}
	}

	/**
	 * takes a full path like http://www.google.com/index.html and turn it into /index.html
	 * 
	 * @param fileName - name of path to parse
	 * @return file name after parsing
	 */
	private String fixProxyFileName(String fileName) {
		StringBuilder result = new StringBuilder();
		String withoutHttp = fileName.substring(7);
		int endOfDomain = withoutHttp.indexOf('/');
		result.append(withoutHttp.substring(endOfDomain));
		return result.toString();
	}

	/**
	 * Receive request from client and pass it to server after verify policies.
	 * 
	 * @param hostName
	 * @param request
	 * @param postBody
	 * @param os
	 * @param isChuncked
	 * @param fileType 
	 * @param originalFullPath 
	 * @throws IOException
	 */
	@SuppressWarnings("resource")
	private void sendRequestToServer(String request, String postBody, 
			DataOutputStream os, boolean isChuncked, String fileType, String policyPath,
			String originalFullPath) throws IOException {
		
		int portFromHeader = 80; // Default port number
		String newHostName = hostName;
		
		// In case port is not 80, check which port is it
		StringTokenizer hostAndPort = new StringTokenizer(hostName, ":");
		try {
			newHostName = hostAndPort.nextToken();
			portFromHeader = Integer.parseInt((hostAndPort.nextToken()));
		} catch (NoSuchElementException e) {
			// This means no port was mentioned so we'll treat it as 80
		}

		// Check if file host name or host address is in policy
		Boolean policyApproved = PolicyCheck(originalFullPath, fileType, policyFile, request);
		if (!policyApproved) {
			sendErrorResponse(os, err.get(403));
			return;
		}

		// We do not support HTTPS
		if (portFromHeader == 443) {
			sendErrorResponse(os, err.get(400));
			return;
		}
		// Make the connection to the real server.
		// If we cannot connect to the server, send 404
		Socket server = null;
		try {
			server = new Socket(newHostName, portFromHeader);
		} catch (IOException e) {
			// Write error to user
			sendErrorResponse(os, err.get(404));
			return;
		}

		// Get server streams.
		final InputStream streamFromServer = server.getInputStream();
		final OutputStream streamToServer = server.getOutputStream();
		final OutputStreamWriter streamWriter = new OutputStreamWriter(streamToServer);
		
		// This thread runs the connection to the server
		Thread connectionToServer = new Thread() {
			public void run() {
				try {
					streamWriter.write(request, 0, request.length());
					if (postBody != null) {
						streamWriter.write(postBody, 0, postBody.length());
					}
					streamWriter.flush();
				} catch (IOException e) {
					System.err.println("Error with writing request to server " + e);
				}
			}
		};
		
		// Start the request thread running
		connectionToServer.start();
		
		// Read the server's responses and pass them back to the client.
		try {
			sendBytes(streamFromServer, os, isChuncked);
		} catch (Exception e) {
			System.err.println("Error with sending data from server to client");
		}
		// Done sending to client. stop thread. close socket.
		try {
			connectionToServer.join();
		} catch (InterruptedException e) {
			System.err.println("Problem with thread join " + e);
		}
		socket.close();
	}
	
	/**
	 * Checks if a certain host and file type are allowed in policy file
	 * @param newHostName - name of host or ip
	 * @param fileType - file type
	 * @param policyFile 
	 * @param request 
	 * @return
	 */
	private Boolean PolicyCheck(String urlAddress, String fileType, File policyFile, String request) {
		Boolean result = true;
		PolicyParser policy = new PolicyParser(policyFile);
		try {
			policy.parseLines();
		} catch (IOException e) {
			e.printStackTrace();
		}
		// Store all parsed policies
		ArrayList<String> blockedSites = policy.getBlockedSites();
		ArrayList<String> blockedResources = policy.getBlockedResources();
		HashMap<Inet4Address, Integer> blockedIpMask = policy.getBlockedIpMask();
		ArrayList<String> blockedCountries = policy.getBlockedCountries();

		
		// Check all blocked sites
		for (String site : blockedSites) {		
			if (urlAddress.contains(site)) {
				result = false;
				writeToLog(request, "blocked-site \"" + site + "\"");
				break;
			}
		}
		// Check all blocked resources
		for (String type : blockedResources) {
			if (type.equalsIgnoreCase(fileType)) {
				result = false;
				writeToLog(request, "blocked-resource \"" + type + "\"");
				break;
			}
		}
		
		// Check all blocked ip's
		int currentIpFromHost;
		try {
			currentIpFromHost = ipIntCreator((Inet4Address) InetAddress.getByName(hostName));
			for (Inet4Address ip : blockedIpMask.keySet()) {
				int blockedIp = ipIntCreator(ip);
				int bits = blockedIpMask.get(ip);
				int mask = -1 << (32 - bits);

				if ((blockedIp & mask) == (currentIpFromHost & mask)) {
				    // IP address is in the subnet.
					result = false;
					writeToLog(request, "blocked-ip-mask \"" + ip.getHostAddress() + "/" + bits +"\"");
					break;
				}
			}
		} catch (UnknownHostException e) {
			// If failed it means the host was not from an IP form so no need to check
		}

		// Check all blocked countries
		ExtensionListParser exParser = new ExtensionListParser(exListFile);

		try {
			exParser.parseLines();
			// Check all blocked resources
			for (String country : blockedCountries) {
				String extenstionBlocked = exParser.getExtension(country);
				String currentExtension = hostName.substring(hostName.lastIndexOf('.') + 1, hostName.length());
				if (extenstionBlocked.equals(currentExtension)) {
					result = false;
					writeToLog(request, "blocked-country \"" + country + "\"");
					break;
				}
			}
		} catch (Exception e) {
			System.err.println("Error parsing extension file " + e);
		}
return result;
	}
	
	/**
	 * Write to log file the following:
	 *  - Time of block.
	 *  - HTTP request that has been blocked.
	 *  - Rule blocked the request.
	 * @param request - blocked request
	 * @param blocked - blocked reason
	 */
	private void writeToLog(String request, String blocked) {
		PrintWriter writer;
		try {
			writer = new PrintWriter(new FileWriter(logFile, true));
			
			// Get time 
			Calendar cal = Calendar.getInstance();
	    	cal.getTime();
	    	SimpleDateFormat time = new SimpleDateFormat("HH:mm:ss  dd.MM.yyyy");
	    	
	    	// Write time to log
	    	writer.println("Time: " + time.format(cal.getTime()));
	    	writer.println();
			
	    	// Write request to log
	    	writer.print(request);
			
	    	//Write blocked reason to log
	    	writer.println(blocked);
			writer.println("-------------------------------------------------------------------------");
			writer.close();
		} catch (IOException e) {
			System.err.println("Error writing into file " + e);
		}	
	}

	/**
	 * IP Address to int
	 * @param ipAddress
	 * @return int representing ip address
	 */
	private int ipIntCreator(Inet4Address ipAddress) {
		byte[] ipArray = ipAddress.getAddress();
		int ipInt = ((ipArray[0] & 0xFF) << 24) | ((ipArray[1] & 0xFF) << 16) |
		        	((ipArray[2] & 0xFF) << 8) | ((ipArray[3] & 0xFF) << 0);
		return ipInt;
	}
	
	/**
	 * Sends server error response according to err
	 * 
	 * @param os
	 * @param err
	 */
	private void sendErrorResponse(DataOutputStream os, Err err) {
		if (!this.socket.isClosed()) {
			try {
				File file = new File(root + err.file);
				FileInputStream fis = new FileInputStream(root + err.file);
				String response = DFLTVERS + " " + err.msg + CRLF;
				String type = "Content-type: " + contentType(err.file) + CRLF;
				String length = "Content-Length: " + file.length() + CRLF;
				os.writeBytes(response);
				os.writeBytes(type);
				os.writeBytes(length);
				os.writeBytes(CRLF);
				System.out.println(response + type + length);
				sendBytes(fis, os, false);
				this.socket.close();
			} catch (Exception e2) {
				System.out.println(e2);
			}
		}
	}

	/**
	 * Parse parameters line
	 * 
	 * @param line - line of parameters to parse
	 * @param parametersSeparated - hashmap to save the parsed parameters to
	 */
	private void paramSeperator(StringBuilder line, HashMap<String, String> parametersSeparated) {
		// separate by '&' sign
		StringTokenizer paramSeparate = new StringTokenizer(line.toString(), "&");

		// Add all the parameters to an array list
		ArrayList<String> parameters = new ArrayList<String>();
		while (paramSeparate.hasMoreTokens()) {
			parameters.add(paramSeparate.nextToken());
		}
		// Parse to key and value
		StringTokenizer keyValueSeparte;

		// For all the different parameters, separate to key and value by "=" sign
		for (String parameter : parameters) {
			keyValueSeparte = new StringTokenizer(parameter, "=");

			// Add the key and value to the hash map
			parametersSeparated.put(keyValueSeparte.nextToken(), keyValueSeparte.nextToken());
		}
	}

	/**
	 * Creates a string which is an HTML code of logs.html which contains
	 * a log of all blocks.
	 * @param deleteLog 
	 * 
	 * @return a string with the html code for the page
	 */
	private String createLogsPage(Boolean deleteLog) {
		StringBuilder logsCode = new StringBuilder();
		logsCode.append("<html><head><title>Proxy Server - Blocks Log</title></head>"
						+ "<body align=\"left\"><h1>Proxy Server - Blocks Log</h1><font face=\"Consolas\">" +
				"<form action=\"logs\" method=\"POST\"><input type=\"submit\" name=\"delete\" value=\"DeleteLog\"></form>");
		FileReader reader = null;
		try {
			if (deleteLog) {
		    	logFile.delete();
		    	logFile.createNewFile();
		    }
		    reader = new FileReader(logFile);
	        int text;
	        while ((text = reader.read()) != -1) {
	        	logsCode.append((char)text);
	        	if ((char)text == '\n') {
		        	logsCode.append("<br>");
	        	}
	        }
	        reader.close();
	    } catch (IOException e) {
			System.err.println("Falied reading from log file " + e);
	    } finally {
	    }
		logsCode.append("</font></body></html>");
		return logsCode.toString();
	}
	
	/**
	 * Creates a string which is an HTML code of editPolicy.html 
	 * @return String html code for page
	 */
	private String createPolicyPage() {
		StringBuilder htmlCode = new StringBuilder();
		htmlCode.append("<html><head><title>Policy Editor</title></head>"
						+ "<body align=\"left\"><h1>Policy Editor</h1>"
				+ "<form action=\"done.html\" method=\"POST\">");
		PolicyParser policyParser = new PolicyParser(policyFile);
		try {
			policyParser.parseLines();
		} catch (IOException e) {
			System.err.println("Failed parsing policy file " + e);
		}
		ArrayList<String> policies = policyParser.getAllFileContent();
		for (String policy : policies) {
			htmlCode.append("<input type=\"radio\" name=\"policy_checked\" value=\"" + policy.replace('\"', '*') + "\" checked>" + policy + "<br>");
		}
		htmlCode.append("<br><input type=\"submit\" name=\"Action\" value=\"Add\"> or " +
							"<input type=\"submit\" name=\"Action\" value=\"Modify\"> to: " +
							"Blocked Category <select name=\"category\">" +
							"<option value=\"block-site\">block-site</option>" +
							"<option value=\"block-resource\">block-resource</option>" +
							"<option value=\"block-ip-mask\">block-ip-mask</option>" +
							"<option value=\"block-country\">block-country *bouns*</option>" +
							"</select> Blocked Content: <input type=\"text\" name=\"modifyValue\" " + 
							"size=\"55\" value=\"e.g: walla.co.il, 212.74.12.6/20, .jpg, Japan\" placeholder=\"e.g: walla.co.il, 212.74.12.6/20, .jpg, Japan\" required>" +
							" or simply <input type=\"submit\" name=\"Action\" value=\"Delete\"><br>" +			
				"</form></body></html>");
		return htmlCode.toString();
	}

	/**
	 * This method receive the following parameters and generate a proper
	 * response
	 * 
	 * @param os - output stream
	 * @param method - name of the http method
	 * @param filename - name of the requested file
	 * @param version - the version of the http request
	 * @param file - the requested file
	 * @param fileExists - boolean that determines if the file is found
	 * @param isChunked - boolean that determines if the file should be chunked
	 * @param fis - file stream
	 * @param trace - the trace of the response
	 * @param parametersSeparated - parameters hash map
	 * @throws Exception - if write to stream fails
	 */
	private void responseBuilder(DataOutputStream os, String method,
			String filename, String version, File file, boolean fileExists,
			boolean isChunked, FileInputStream fis, String trace) throws Exception {

		// Construct the response message.
		StringBuilder response = new StringBuilder();
		String statusLine = null;
		String contentTypeLine = null;
		String status = null;

		// If method doesn't exist send 501
		if (!method.equals("POST") && !method.equals("GET")
				&& !method.equals("TRACE") && !method.equals("OPTIONS") && !method.equals("HEAD")) {
			sendErrorResponse(os, err.get(501));
			return;
		} else {
			// If file doesn't exist, send 404
			if (!fileExists) {
				sendErrorResponse(os, err.get(404));
				return;
			} else {
				status = "200 OK";
			}
		}

		// Create headers
		statusLine = version + " " + status + " " + CRLF;
		contentTypeLine = "Content-type: " + contentType(filename) + CRLF;

		// writes the file to the output stream
		os.writeBytes(statusLine); // Send the status line.
		os.writeBytes(contentTypeLine); // Send the content type line.

		response.append(statusLine);
		response.append(contentTypeLine);

		// If the method is options, add the options header
		if (method.equals("OPTIONS")) {
			String options = "Allow: GET, HEAD, POST, TRACE, OPTIONS" + CRLF;
			os.writeBytes(options);
			response.append(options);
		}

		// Send the file size if not chunked
		if (isChunked) {
			String transferEncoding = "Transfer-Encoding: chunked" + CRLF;
			os.writeBytes(transferEncoding);
			response.append(transferEncoding);
		} else {
			String contentLength = "Content-Length: " + file.length() + CRLF;
			os.writeBytes(contentLength);
			response.append(contentLength);
		}

		// Send a blank line to indicate the end of the header lines.
		os.writeBytes(CRLF);

		// If the method is trace, head or options, do not return file
		if (method.equals("GET") || method.equals("POST")) {
			sendBytes(fis, os, isChunked);

		// If the method is TRACE return the headers from the request
		} else if (method.equals("TRACE")) {
			if (isChunked) {
				int length = trace.length();
				int i = 0;
				byte[] b = trace.getBytes();
				while (length >= CHUNK) {
					os.writeBytes(CHUNKHEX + CRLF);
					os.write(b, i * CHUNK, CHUNK);
					os.writeBytes(CRLF);
					i++;
					length -= CHUNK;
				}
				if (length != 0) {
					os.writeBytes(Integer.toHexString(length) + CRLF);
					os.write(b, i * CHUNK, length);
					os.writeBytes(CRLF);
				}
				os.writeBytes("0" + CRLF + CRLF);
			} else {
				os.writeBytes(trace);
			}
		}

		// Print the headers
		System.out.println(response);

		// Close streams and socket.
		fis.close();
		os.close();
	}

	/**
	 * return the file types
	 * 
	 * @param fileName
	 * @return String file type
	 */
	private static String contentType(String fileName) {
		if (fileName.endsWith(".htm") || fileName.endsWith(".html")) {
			return "text/html";
		}
		if (fileName.endsWith(".bmp") || fileName.endsWith(".gif")
				|| fileName.endsWith(".png") || fileName.endsWith(".jpg")) {
			return "image";
		}
		if (fileName.endsWith(".ico")) {
			return "icon";
		}
		return "application/octet-stream";
	}

	/**
	 * set up input output streams
	 * 
	 * @param fis - file stream of the relevant file
	 * @param os - output stream
	 * @param isChunked - boolean that determines if the file should be chunked
	 * @throws Exception - when write to stream failed
	 */
	private void sendBytes(FileInputStream fis, DataOutputStream os,
			boolean isChunked) throws Exception {
		// Construct a 10K buffer to hold bytes on their way to the socket.
		byte[] buffer = new byte[10240];
		int bytes = 0;
		int i = 0;

		// Copy requested file into the socket's output stream.
		while ((bytes = fis.read(buffer)) != -1) {
			if (isChunked) {
				while (bytes >= CHUNK) {
					os.writeBytes(CHUNKHEX + CRLF);
					os.write(buffer, i * CHUNK, CHUNK);
					os.writeBytes(CRLF);
					i++;
					bytes -= CHUNK;
				}
				if (bytes != 0) {
					os.writeBytes(Integer.toHexString(bytes) + CRLF);
					os.write(buffer, i * CHUNK, bytes);
					os.writeBytes(CRLF);
				}
				os.writeBytes("0" + CRLF + CRLF);
			} else {
				os.write(buffer, 0, bytes);

			}
		}
	}

	/**
	 * set up input output streams
	 * 
	 * @param inputStream - stream of the relevant file
	 * @param os - output stream
	 * @param isChunked - boolean that determines if the file should be chunked
	 * @throws Exception - when write to stream failed
	 */
	private void sendBytes(InputStream inputStream, DataOutputStream os,
			boolean isChunked) throws Exception {
		// Construct a 10K buffer to hold bytes on their way to the socket.
		byte[] buffer = new byte[10240];
		int bytes = 0;
		int i = 0;
		// Copy requested file into the socket's output stream.
		while ((bytes = inputStream.read(buffer)) != -1) {
			if (isChunked) {
				while (bytes >= CHUNK) {
					os.writeBytes(CHUNKHEX + CRLF);
					os.write(buffer, i * CHUNK, CHUNK);
					os.writeBytes(CRLF);
					i++;
					bytes -= CHUNK;
				}
				if (bytes != 0) {
					os.writeBytes(Integer.toHexString(bytes) + CRLF);
					os.write(buffer, i * CHUNK, bytes);
					os.writeBytes(CRLF);
				}
				os.writeBytes("0" + CRLF + CRLF);
			} else {
				os.write(buffer, 0, bytes);
			}
		}
		os.flush();
	}

}