// 201530722
// 029983111

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class proxyServer {
	public static void main(String argv[]) {

		File configFile = new File("config.ini");
		ConfigParser parser = new ConfigParser(configFile);
		try {
			parser.parseLines();
		} catch (IOException e) {
			e.printStackTrace();
		}
		String policyPath = "policy.ini"; // Some default policy file
		if (argv.length > 0) {
			policyPath = argv[0];	
		}
		
		// Set the port number.
		int port = parser.getPort();
		int maxThreads = parser.getMaxThreads();

		ExecutorService pool = Executors.newFixedThreadPool(maxThreads);
		
		// Establish the listen socket.
		ServerSocket socket;
		try {
			socket = new ServerSocket(port);
			
			// Process HTTP service requests in an infinite loop.
			while (true) {
				// Listen for a TCP connection request.
				Socket connectionSocket = socket.accept();
				// Construct an object to process the HTTP request message.
				MyHttpRequest request = new MyHttpRequest(connectionSocket, policyPath);
				pool.execute(request);
			}
		} catch (Exception e) {
			System.out.println("Error with sockets");
			e.printStackTrace();
		} finally {
			pool.shutdown();
		}
		
	}
}