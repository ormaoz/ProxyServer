== Or Maoz ==

-- Instructions: 
1. Place folder serverroot at C: drive
2. click compile.bat
3. click run.bat
4. enter browser and set it up to use proxy
5. enjoy our proxy server :-)

-- Please note -- 
1. We do not support HTTPS request
	Some website may appear as they are not running using https but in fact some object in them are sent using https.
	best way to deal with this problem is to define the browser to use proxy NOT for HTTPS requests.

-- Java Files --
1. Config Parser.java - A class made to parse the config file
2. ExtensionListParser.java - Part of the bonus. We added the option to block request for spesific countries!
						the blocking is based on a the domainExList.ini file which is parsed by ExtensionListParser.java
						and then we can tell which domain suffix is for each country.
3. MyHttpRequest.java - This is where the magic happens! get a request from browser, check if it's for proxy or for other server. 
					if for proxy, deal with it (logs / policies) and if for server, check policies and if ok, pass to server and 
					send response from server to client.
4. PolicyParser.java - Parse the policy file
5. proxyServer.java - Main class! recieves as argument a policy file and open thread for every client request.

-- txt files --
1. bonus.txt - spcify the bonus we did.
2. readme.txt - :-)

-- config files --
1. config.ini - define directories and other parameters
2. domainExList.ini - a list of all country domain suffix in the world
3. police.ini - policies for the proxy server 

-- other files --
1. output.log - keeps log of all blocks.
2. compile.bat - comppile all java files.
3. run.bat - run proxyServer with argument police.ini

-- serverroot folder --
1. 400.html - error 400
2. 403.html - error 403
3. 404.html - error 404
4. 500.html - error 500
5. 501.html - error 501
6. done.html - temp page for when request send to server
7. editPolicy.html - the page to edit policies
8. logs.html - all the logs in html page