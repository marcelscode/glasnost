#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>
#include <netinet/tcp.h>


#include <linux/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>

#include "glasnost_replayer.h"
#include "tools.h"

#define ETH_DEV "eth0" // default
#define CONNECT_TIMEOUT 20
#define DEFAULT_TEST_DURATION 10
#define MAXIMUM_TEST_DURATION 30

#define UPSTREAM 0
#define DOWNSTREAM 1

int token = 0; // Anonymize peer's IP address

// TODO Add functionality to check whether packets were altered in flight
//      - Mark when there is unpredictable content in a file
//      - glasnost_replayer.h already as a function to do the check
// TODO Integrate warmupSocket to avoid caching artifacts

// TODO
// to make it possible to reuse the same port, the following has to be done (the keep-processes approach)
// - Has synchronization problem
// - retry when binding to the port fails (X times, wait for X ms between tries)
// - Check whether the connecting host is the one we are waiting for (already done)
// - On the client side, retry after X ms if the connection was closed immediately
//
// the thread approach (less robust!)
// - Have a socket management thread that has an interface to request connections
// - it dispatched (passes on) connected sockets to the thread that requested it (callback)



void handle_sigpipe(int x){} // Ignore

GlasnostReplayer::~GlasnostReplayer()
{
  GlasnostParser::freeProtocolScript(protocolScript);
}

GlasnostReplayer::GlasnostReplayer(int cs)
{
	assert(cs >= 0);

	this->cs = cs;
	this->readSocket = -1;
	reset();

	ethDev = ETH_DEV;
	setPorts(0, 0);

	//signal(SIGPIPE, SIG_IGN);
	signal(SIGPIPE, handle_sigpipe);

	stream = stdout;
}

int GlasnostReplayer::openRawSocket(const string device)
{
	/*
	int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock<0) {
		if (errno == EPERM)
			panic("Cannot open raw socket on %s: Need to be root?", device);
		else
			panic("Cannot open raw socket on %s (errno=%d)", device, errno);
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
		panic("Cannot get the interface index of %s (errno=%d)", device, errno);

	struct sockaddr_ll ll;
	memset(&ll, 0, sizeof(ll));
	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = ifr.ifr_ifindex;
	ll.sll_protocol = htons(ETH_P_ALL);
	if (bind(sock, (struct sockaddr*)&ll, sizeof(ll)) < 0)
		panic("Cannot bind to raw socket on %s (errno=%d)", device, errno);

	return sock;
	*/

    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    capture = pcap_open_live(device.c_str(), BUFSIZ, 0, -1, errbuf);
    if (capture == NULL)
		panic("Cannot start capturing packets with pcap: %s\n", errbuf);

    // Filter for packets from/to our peer
    char filter[32];
    snprintf(filter, 32, "host %d.%d.%d.%d", (int)peer&0xFF, (int)(peer>>8)&0xFF, (int)(peer>>16)&0xFF, (int)(peer>>24)&0xFF);
	if (pcap_compile(capture, &fp, filter, 0, 0) == -1)
		panic("Error calling pcap_compile: %s", pcap_geterr(capture));

	if (pcap_setfilter(capture, &fp) == -1)
		panic("Error setting pcap filter\n");
	pcap_freecode(&fp);

    int fd = pcap_get_selectable_fd(capture); // According to the man page, this only works for *nix
    if(fd < 0)
    	panic("Cannot get selectable file descriptor for pcap capture.");

	return fd;
}

/**
 * Extract the protocol name from the script preamble
 * If the protocol's name was found, returns a pointer to a allocated
 * buffer containing the protocol's name. Null otherwise.
 */
char *GlasnostReplayer::getProtocol(char *line){

	if(strncmp(line, "[protocol:", 10) != 0)
		return NULL;

	char *proto, *tok;
	proto = strtok_r(&line[10], " ", &tok);

	// Is there a trailing ']'?
	if(strchr(proto, ']') == NULL)
		return strndup(proto, strlen(proto));
	else
		return strndup(proto, strlen(proto)-1);
}


bool GlasnostReplayer::readInScript(const vector<string> &proto, vector<string> &unknownProtocol)
{
	// TODO Simplify, when protocol is found, just read it in

	// 1. Load file
	// 2. Read in file and count lines per protocol for allocation
	//    Also check whether all protocols are present
	// 3. Read in each protocol that was requested

	assert(proto.size() > 0);
	assert(scriptFile.length() > 0);

	if((scriptFile.compare(0, 7, "http://") == 0) || (scriptFile.compare(0, 8, "https://") == 0) || (scriptFile.compare(0, 6, "ftp://") == 0)){
		// Check the passed URL first before downloading it
		if(checkUrl(scriptFile))
			scriptFile = fetchScriptFile(scriptFile, scriptDir);
		else
			return false;
	}
	if((scriptFile.length() <= 0) || access(scriptFile.c_str(), R_OK)){
		error(stream, "Not script file or cannot access it: %s", scriptFile.c_str());
		return false;
	}

	// Read in scriptFile, check whether all protocols are there and count the number of lines for each
	string errorMsg;
	if (!GlasnostParser::parseScript(scriptFile, protocolScript, errorMsg)) {	  
	  error(stream, "Error while parsing protocol file %s:\n%s", scriptFile.c_str(), errorMsg.c_str());
	  return false;
	}

	debug(stream, "Found %d protocols in file %s", protocolScript.size(), scriptFile.c_str());	
	//DEBUG
	//GlasnostParser::ProtocolScript& pscript = protocolScript; 
	//for (GlasnostParser::ProtocolScript::iterator i = pscript.begin();
	//   i != pscript.end(); ++i) {
	  

	//cout << "protocol " << i->first << "&port1=" << i->second.port1 << " port2=" << i->second.port2 << " with " << i->second.commands.size() << " commands\n";
	  //for (unsigned int n = 0; n < i->second.commands.size(); ++n)
	    //cout << n + 1 << ": " << *(i->second.commands[n]) << endl;	  

	//}
	//END DEBUG
	//Check if all protocools are present, otherwise complain
	bool all_known = true;
	for (unsigned int i = 0; i < proto.size(); ++i) {
	  if (protocolScript.find(proto[i]) == protocolScript.end()) {	    
	    debug(stream, "Could not find protocol %s in %s", proto[i].c_str(), scriptFile.c_str());
	    unknownProtocol.push_back(proto[i]);
	    all_known = false;
	  }
	}	

	if (!all_known) {
	  GlasnostParser::freeProtocolScript(protocolScript);
	  debug(stream, "Some of the requested protocols were not found in file %s", scriptFile.c_str());
	  return false;
	}	

	return true;
}


/**
 * Check URL whether it is OK to download
 * At this point, it is only OK to download from the local IP or broadband.mpi-sws.mpg.de
 */
bool GlasnostReplayer::checkUrl(string url){

	// Get the IP address of the server
	size_t p = url.find("://");
	if(p != url.npos){
		url = url.substr(p+3);
	}
	p = url.find("/");
	if(p != url.npos){
		url = url.substr(0, p);
	}
	p = url.find(":");
	if(p != url.npos){
		url = url.substr(0, p);
	}

	struct addrinfo hints, *res;
	memset (&hints, 0, sizeof (hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_CANONNAME;

	int errcode = getaddrinfo(url.c_str(), NULL, &hints, &res);
	if (errcode != 0){
		error(stream, "getaddrinfo failed for %s", url.c_str());
		return false;
	}
	unsigned long urlAddress = *(&((struct sockaddr_in *) res->ai_addr)->sin_addr.s_addr);

	/* Example code that can also handle IPv6
	while (res){
		void *ptr;
		char addrstr[100];
		inet_ntop (res->ai_family, res->ai_addr->sa_data, addrstr, 100);

		switch (res->ai_family){
		case AF_INET:
			ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
			break;
		case AF_INET6:
			ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
			break;
		}
		inet_ntop (res->ai_family, ptr, addrstr, 100);
		printf ("IPv%d address: %s (%s)\n", res->ai_family == AF_INET6 ? 6 : 4,
				addrstr, res->ai_canonname);
		res = res->ai_next;
	}
	freeaddrinfo(res);
	 */


	// Check whether the host in the URL is the local host
	int sd;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));

	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0){
	    error(stream, "Cannot allocate socket (%s)", strerror(errno));
	    return false;
	}
	strncpy(ifr.ifr_name, ethDev.c_str(), IFNAMSIZ);
	if (ioctl(sd, SIOCGIFADDR, &ifr) == -1) {
		error(stream, "Cannot get IP address of device %s: %s", ethDev.c_str(), strerror(errno));
	} else {
		struct sockaddr_in localAddress;
		memcpy((char *) &localAddress, (char *) &ifr.ifr_addr, sizeof(localAddress));

		if(urlAddress == localAddress.sin_addr.s_addr)
			return true;
	}

	// Now check whether the host in the URL is broadband.mpi-sws.org
	memset (&hints, 0, sizeof (hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_CANONNAME;

	errcode = getaddrinfo("broadband.mpi-sws.mpg.de", NULL, &hints, &res);
	if (errcode != 0){
		perror("getaddrinfo");
		error(stream, "getaddrinfo failed for %s", "broadband.mpi-sws.mpg.de");
		return false;
	}

	if(urlAddress == *(&((struct sockaddr_in *) res->ai_addr)->sin_addr.s_addr))
		return true;

	return false;
}

/**
 * Communicate with the measurement server and start individual tests
 */

void GlasnostReplayer::run()
{
	char buffer[4096];
	char backLog[32000];
	int backLog_p = 0;
	backLog_p += sprintf(backLog, "log ");

	pcap_t *myPcap = NULL;
	myDumper = NULL;
	char dumpFile[500];
	char logFile[500];

	char peerName[500];
	char peerIP[64];
	struct sockaddr_in from;
	int len = sizeof(from);

	int numUnknownCommands = 0;

	int ret;

	stream = stdout;

	if (getsockname(cs, (struct sockaddr*) &from, (socklen_t*) &len) < 0) {
		error(stream, "Cannot get parameters of command socket. (errno=%d)", errno);
		perror("getsockname");
		cleanupAndExit();
	}
	commandPort = ntohs(from.sin_port);

	if (getpeername(cs, (struct sockaddr*) &from, (socklen_t*) &len) < 0) {
		error(stream, "Cannot get IP address of connected client. (errno=%d)", errno);
		perror("getpeername");
		cleanupAndExit();
	}

	peer = from.sin_addr.s_addr;

	ret = getnameinfo((struct sockaddr *) &from, sizeof(from), peerName, 500, NULL, 0, 0);
	if (ret != 0) {
		error(stream, "Cannot resolve hostname (errno: %d)", ret);
		snprintf(peerName, 500, "%d.%d.%d.%d", (int)peer&0xFF, (int)(peer>>8)&0xFF, (int)(peer>>16)&0xFF, (int)(peer>>24)&0xFF);
	}

	struct timeval mstart;
	gettimeofday(&mstart, NULL);
	snprintf(peerIP, 64, "%d.%d.%d.%d", (int)peer&0xFF, (int)(peer>>8)&0xFF, (int)(peer>>16)&0xFF, (int)(peer>>24)&0xFF);

	// Nagios check connections
	if(!strncmp(peerName, "hi.tech.org", 11) || !strncmp(peerIP, "149.20.53.171", 13))
	{
		char peerMsg[500];
		memset(peerMsg, 0, sizeof(peerMsg));
		snprintf(peerMsg, sizeof(peerMsg), "ip %s %s id %d \n", peerIP, peerName, (int)mstart.tv_sec);
		ret = write(cs, peerMsg, strlen(peerMsg));
		cleanupAndExit();
	}

	if(logDir.compare("--") != 0){
		snprintf(logFile, 500, "%s/glasnost_%s_%s_%d.log", logDir.c_str(), peerIP, peerName, (int)mstart.tv_sec);

		if ((stream = fopen(logFile, "a")) == NULL) {
			error(stream, "Failed to open file %s (errno: %d)", logFile, errno);
			cleanupAndExit();
		}
		log(stdout, "Saving log to %s", logFile);
	} else {
		stream = stdout;
		logDir = ".";
	}

	log(stream, "Client %s %d.%d.%d.%d connected (port %d)", peerName, (int)peer&0xFF, (int)(peer>>8)&0xFF, (int)(peer>>16)&0xFF, (int)(peer>>24)&0xFF, ntohs(from.sin_port));

	if ((ports[0] > 0) || (ports[1] > 0))
		log(stream, "Using ports %d and %d for measurements (overwrite).", ports[0], ports[1]);

	// Tell the client
	char peerMsg[500];
	memset(peerMsg, 0, sizeof(peerMsg));
	snprintf(peerMsg, sizeof(peerMsg), "ip %s %s id %d \n", peerIP, peerName, (int)mstart.tv_sec);
	ret = write(cs, peerMsg, strlen(peerMsg));
	if ((ret < 0) || ((unsigned int) ret < strlen(peerMsg))) {
		error(stream, "Cannot write to command socket.");
		cleanupAndExit();
	}


	// Now listen on command socket for commands and run transfers
	unsigned char cbuff[20000];
	unsigned int cbuff_p = 0;
	struct sockaddr_in addr;

	bool connectionTerminated = false;

	int exp = 0;
	while(!connectionTerminated){

		bool commandFound = false;

		while ((!connectionTerminated) && (!commandFound)) {
			for (unsigned int i = 0; (i < cbuff_p) && (!commandFound); i++) {
			  if (cbuff[i] == '\n') {  //|| cbuff[i] == '\r' /* DEBUG to be removed -- only used so that telnet can work with the server */) {
					for (unsigned int n = 0; n <= i; n++)
						buffer[n] = cbuff[n];
					buffer[i] = 0;

					for (unsigned int n = i + 1; n < cbuff_p; n++)
						cbuff[n-(i+1)] = cbuff[n];

					cbuff_p -= (i+1);

					commandFound = true;
				}
			}

			if (!commandFound) {
				// Read from command_socket
				if ((cbuff_p+1) >= sizeof(cbuff)){
					error(stream, "Command buffer overflow (%u >= %zu)", cbuff_p, sizeof(cbuff));
					connectionTerminated = true;
					break;
				}

				struct timeval tv;
				gettimeofday(&tv, NULL);
				tv.tv_sec += 20;
				if (sniffPackets(cs, readSocket, &tv, peer) == 1){
					error(stream, "Peer did not give me commands (%d).", (int)tv.tv_sec);
					connectionTerminated = true;
					break;
				}

				int ret = read(cs, &cbuff[cbuff_p], sizeof(cbuff) - cbuff_p);
				if (ret == -1){
					error(stream, "Failed to read commands.");
					connectionTerminated = true;
					break;
				} else if (ret == 0)
					connectionTerminated = true;

				//log(stream, "We read %d bytes from command socket (%d).", ret, ntohs(from.sin_port));
				//dump(stream, &cbuff[cbuff_p], ret, 4); // DEBUG

				cbuff_p += ret;
			}
		}

		if (connectionTerminated)
			break;
		assert(commandFound);

		// Read in commands and execute them
		// Format: replay <Protocol> <server/client> <duration> port <port>
		//      or <Command> [...]

		int port, duration;
		bool isServer = false;
		bool sendControlFlow = false;
		char protocol[200];

		if (!strncmp(buffer, "replay ", 7)) {
		} else if (!strncmp(buffer, "shutdown", 8)) {
			connectionTerminated = true;
			break;
		} else if (!strncmp(buffer, "areyouthere", 11)){

			log(stream, "Command: areyouthere");

			// Send back an "yes\n" to the server
			ret = write(cs, "yes\n", 4);
			if (ret < 4){
				connectionTerminated = true;
				error(stream, "Cannot write to command socket (yes).");
			}

			connectionTerminated = true;

			fclose(stream);
			stream = stdout;
			remove(logFile);

			cleanupAndExit();
		} else if (!strncmp(buffer, "log", 3)) {
			log(stream, "Client: %s", (char *)(&buffer[4]));
			continue;
		} else if (!strncmp(buffer, "script ", 7)) {
			scriptFile = fetchScriptFile(&buffer[7], scriptDir);

			if(scriptFile.compare("") == 0){
				char obuf[32];
				snprintf(obuf, 32, "no script\n");
				ret = write(cs, obuf, strlen(obuf));
				if ((ret < 0) || ((unsigned int) ret < strlen(obuf))){
					connectionTerminated = true;
					error(stream, "Cannot write to command socket (no script).");
				}
				cleanupAndExit();
			} else {
				// Send back an "ok\n" to the server
				ret = write(cs, "ok\n", 3);
				if (ret < 3) {
					connectionTerminated = true;
					error(stream, "Cannot write to command socket (ok).");
					cleanupAndExit();
				}
			}
			continue;
		} else if (!strncmp(buffer, "protos ", 7)) {

			char *proto;
			char *tok;
			int numProtocols = 0;			
			
			// Tokenize semicolon separated protocol list
			proto = strtok_r(&buffer[7], ";", &tok);
			while(proto != NULL){
				numProtocols ++;
				//printf("proto:%sll\n", proto);
				//debug(stream, "%d: %s", numProtocols, proto);
				
				protocols.push_back(proto);
				proto = strtok_r(NULL, ";", &tok);
			}			

			vector<string> unknownProtocols;
			if(!readInScript(protocols, unknownProtocols)){


			  char obuf[strlen(buffer)+15];
			  memset(obuf, 0, sizeof(obuf));
			  if(unknownProtocols.size() <= 0){
			    snprintf(obuf, sizeof(obuf), "no proto\n");
			  } else {
			    string unknown = unknownProtocols[0];
			    for(unsigned int i=1; i<unknownProtocols.size(); i++)
			      unknown += ';' + unknownProtocols[i];
			    
			    debug(stream, "Reporting back that I do not know the following protocols: %s", unknown.c_str());
			    snprintf(obuf, sizeof(obuf), "unknown proto %s\n", unknown.c_str());
			  }
			  
			  ret = write(cs, obuf, strlen(obuf));
			  if ((ret < 0) || ((unsigned int) ret < strlen(obuf))){
			    connectionTerminated = true;
			    error(stream, "Cannot write to command socket (unknown proto).");
			  }

				cleanupAndExit();
			} else {
				// Send back an "ok\n" to the server
			
			  
				ret = write(cs, "ok\n", 3);
				if (ret < 3) {
					connectionTerminated = true;
					error(stream, "Cannot write to command socket (ok).");
					cleanupAndExit();
				}
			}

			continue;
		} else {
			error(stream, "Unknown command: %s", buffer);
			if(++numUnknownCommands > 3) {
				error(stdout, "%s (%s) sent 4 wrong commands, aborting.", peerName, peerIP);
				fclose(stream);
				stream = stdout;
				remove(logFile);
				cleanupAndExit();
			}
			continue;
		}

		// We got that far, so there was a request to replay a protocol then

		// Setting up packet sniffing
		if (readSocket <= 0){
			snprintf(dumpFile, 500, "%s/glasnost_%s_%s_%d.dump", logDir.c_str(), peerIP, peerName, (int)mstart.tv_sec);
			log(stream, "Saving trace to %s", dumpFile);

			// Make the sniffing (raw) socket non-blocking
			readSocket = openRawSocket(ethDev);
			int flags = fcntl(readSocket, F_GETFL, &flags);
			if (flags<0)
				panic("Cannot F_GETFL the raw socket");
			flags |= O_NONBLOCK;

			int err = fcntl(readSocket, F_SETFL, flags);
			if (err<0)
				panic("Cannot F_SETFL the raw socket (errno=%d)", errno);

			myPcap = pcap_open_dead(DLT_RAW, 4096);
			if (!myPcap)
				panic("Cannot initialize libpcap");

			myDumper = pcap_dump_open(myPcap, dumpFile);
			if (!myDumper)
				panic("Cannot create pcap trace: '%s'", dumpFile);
		}

		char *arg[20];
		char *tok;
		arg[0] = strtok_r(buffer, " ", &tok);
		for (int i = 1; i < 20; i++)
			arg[i] = arg[i-1] ? strtok_r(NULL, " ", &tok) : NULL;

		strncpy(protocol, arg[1], sizeof(protocol));

		if (!strcmp(arg[2], "server")){
			isServer = true;
		} else if(!strcmp(arg[2], "client")){
			isServer = false;
		} else{
			fprintf(stderr, "Malformed command: %s\n", buffer);
			continue;
		}

		duration = atoi(arg[3]);
		if(duration <= 0)
			duration = DEFAULT_TEST_DURATION;
		else if(duration > MAXIMUM_TEST_DURATION)
			duration = MAXIMUM_TEST_DURATION;
		if (strcmp(arg[4], "port")){
			error(stream, "Malformed command: %s\n", buffer);
			continue;
		}
		port = atoi(arg[5]);

		if(arg[6] != NULL){
			if(!strcmp(arg[6], "controlFlow"))
				sendControlFlow = true;
		}

		fprintf(stream, "%lld Received: replay %s ", (getTimeMicros()/1000LL), protocol);
		if (isServer)
			fprintf(stream, "as server ");
		else
			fprintf(stream, "as client ");
		fprintf(stream, "on port %d for %d seconds", port, duration);
		if (sendControlFlow)
			fprintf(stream, " as a control flow");

		fprintf(stream, ".\n");

		// If special ports -1 and -2 are given, the client signals us to
		// choose either a bad (ports[0]) or a good (ports[1]) port.
		// bad = potentially shaped port; good = potentially unshaped port
		bool portOverwrite = false;
		if (port == -1){
			fprintf(stream, "%lld Overwriting port %d with %d\n", (getTimeMicros()/1000LL), port, ports[0]);
			port = ports[0];
			portOverwrite = true;
		} else if (port == -2){
			fprintf(stream, "%lld Overwriting port %d with %d\n", (getTimeMicros()/1000LL), port, ports[1]);
			port = ports[1];
			portOverwrite = true;
		}

		// Now start the experiment
		struct timeval start, end;
		int sock;

		/* Get a socket */
		if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
			panic("Cannot create socket\n");

		int on = 1;
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

		// Set timeout values for this socket for reading/writing
		struct timeval to;
		to.tv_sec = 1; to.tv_usec = 0;
		setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(struct timeval));
		to.tv_sec = 1; to.tv_usec = 0;
		setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &to, sizeof(struct timeval));

		/* Bind to the given port */
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = htons(port);

		int retries = 2;
		while (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0){
			//perror("Error");
			if(retries > 0){
				error(stream, "bind() failed for port %d, trying again. (%d)", port, errno);

				// Wait half a second before retrying
				struct timeval to;
				gettimeofday(&to, NULL);
				to.tv_usec += 500000;
				sniffPackets(sock, readSocket, &to, peer);

				retries--;
				continue;
			}

			error(stream, "bind() failed for port %d, letting the kernel choose another port (errno: %d)", port, errno);

			memset(&addr, 0, sizeof(addr));
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = INADDR_ANY;
			addr.sin_port = 0; // Let the kernel choose a port for us
		}
/*
 		ret = -1;
		while(ret < 0){
			ret = bind(sock, (struct sockaddr*)&addr, sizeof(addr));

			if(ret < 0){
				//perror("Error");
				error(stream, "bind() failed for port %d, trying another port (errno: %d)", port, errno);

				memset(&addr, 0, sizeof(addr));
				addr.sin_family = AF_INET;
				addr.sin_addr.s_addr = INADDR_ANY;
				addr.sin_port = 0; // Let the kernel choose a port for us
			}
			else{
				if(addr.sin_port == 0){
					socklen_t len = sizeof(addr);
					ret = getsockname(sock, (struct sockaddr*)&addr, &len);
					assert(ret >= 0);
					port = ntohs(addr.sin_port);

					addr.sin_port = 0;
					if((port != 6881) && (port != 4711))
						break;
				}
			}
		}
*/
		// Set it to listen
		if (listen(sock, 1) < 0)
			panic("listen() failed\n");

		if ((addr.sin_port == 0) || portOverwrite){
			socklen_t len = sizeof(addr);
			ret = getsockname(sock, (struct sockaddr*)&addr, &len);
			assert(ret >= 0);
			port = ntohs(addr.sin_port);

			// Tell the client on what port we are
			log(stream, "Telling the client to use port %d.", port);
			char portMsg[50];
			snprintf(portMsg, 50, "port %d ok\n", port);
			ret = write(cs, portMsg, strlen(portMsg));
			if ((ret < 0) || ((unsigned int) ret < strlen(portMsg))){
				error(stream, "Cannot write to command socket.");
				connectionTerminated = true;
				close(sock);
				cleanupAndExit();
			}
		} else {
			// Send back an "ok\n" to the server
			ret = write(cs, "ok\n", 3);
			if(ret < 3){
				connectionTerminated = true;
				error(stream, "Cannot write to command socket.");
				close(sock);
				cleanupAndExit();
			}
		}

//		log(stream, "Listening on port %d", ntohs(addr.sin_port));

		int fd = -1;
		while (1) {
			// Wait for at most 30 seconds for the client to connect
			struct timeval to;
			gettimeofday(&to, NULL);
			to.tv_sec += 30;
			if (sniffPackets(sock, readSocket, &to, peer) == 1){
				error(stream, "Accept timeout: Peer did not show up.");
				close(sock);
				break;

				//connectionTerminated = true;
				//fclose(stream);
				//cleanupAndExit();
			}

			// Accept the incoming connection
			struct sockaddr_in from;
			int len = sizeof(from);
			fd = accept(sock, (struct sockaddr*)&from, (socklen_t*)&len);
			if (fd < 0){
				error(stream, "Cannot accept new connection: %d", errno);
				close(sock);
				cleanupAndExit();
			}

			// Check if the connecting host is the one we are interested in
			if ((peer != 0) && (from.sin_addr.s_addr != peer)){
				log(stream, "Connection from %d.%d.%d.%d not accepted as we filter for %d.%d.%d.%d", from.sin_addr.s_addr&0xFF, (from.sin_addr.s_addr>>8)&0xFF, (from.sin_addr.s_addr>>16)&0xFF, (from.sin_addr.s_addr>>24)&0xFF, (int)peer&0xFF, (int)(peer>>8)&0xFF, (int)(peer>>16)&0xFF, (int)(peer>>24)&0xFF);
				close(fd);
				continue;
			}


			// Setting the TCP_NODELAY option here disable Nagle's algorithm for the socket
			// What this means is that the TCP socket will NOT wait until it buffers MSS bytes before
			// sending a packet. This is needed to faithfuly replay a trace where packets smaller than MSS
			// are sent. Unfortunately, it's not enough to preserve the packets of the original trace, because
			// messages are still buffered by the socket when no packet can be sent and then sent later breaking the message boundaries
			int val = 1;
			if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void*) &val, sizeof(val)) < 0) {
			  error(stream, "Error while setting TCP_NODELAY : %d", errno);
			  perror("while setting TCP_NODELAY : ");
			  close(fd);
			  cleanupAndExit();			  
			}
			log(stream, "Enabled TCP_NODELAY option for socket");

			close(sock);
			break;
		}

		// Now run transfer
		reset();
		log(stream, "Running %s%s as %s on port %d .", (sendControlFlow?"control flow of ":""), protocol, isServer?"server":"client", port);
		bool transferSuccessful = runTransfer(fd, protocol, duration, isServer, &start, &end, sendControlFlow);
		double timespan;
		if ((end.tv_usec - start.tv_usec) >= 0)
			timespan = (end.tv_sec - start.tv_sec) + ((end.tv_usec - start.tv_usec)/1000000.0);
		else
			timespan = (end.tv_sec - start.tv_sec -1) + ((1000000 + end.tv_usec - start.tv_usec)/1000000.0);

		if(timespan < 0)
			timespan = 0;

		backLog_p += sprintf(&backLog[backLog_p], "expsu%d=%.0f&expsd%d=%.0f&expsl%d=%.3f&expsstate%d=%d&", exp, bytesTransmitted, exp, bytesReceived, exp, timespan, exp, lastState);
		if (transferSuccessful){
			log(stream, "Transmitted %.0f bytes and received %.0f bytes in %.3f seconds: %.0f %0.f bps (state=%d)", bytesTransmitted, bytesReceived, timespan, (timespan>0)?(bytesTransmitted*8/timespan):0, (timespan>0)?(bytesReceived*8/timespan):0, lastState);
		} else {
			if (timespan > 0)
				log(stream, "FAILED: Transmitted %.0f bytes and received %.0f bytes in %.3f seconds: %.0f %0.f bps (state=%d)", bytesTransmitted, bytesReceived, timespan, (timespan>0)?(bytesTransmitted*8/timespan):0, (timespan>0)?(bytesReceived*8/timespan):0, lastState);
			else
				log(stream, "FAILED: %s as %s", protocol, isServer?"server":"client");
			backLog_p += sprintf(&backLog[backLog_p], "expsr%d=%d&expsrs%d=%d&", exp, resetsReceived, exp, resetsSent);
		}
		exp ++;

		assert(backLog_p < 32000);

		// Clean up
		if(fd >=0){
			setNonblocking(fd);
			close(fd);
		}

		// Flush out captured packets
		//pcap_dump_flush(myDumper); // Not supported by version installed on PlanetLab
	}

	// Listen for 2 seconds for more incoming packets
	//gettimeofday(&tv, NULL);
	//tv.tv_sec += 1;
	//tv.tv_usec += 500000;
	//sniffPackets(-1, read_socket, &tv, peer);

	// Send back aggregated results here.
	backLog[backLog_p] = '\n';
	backLog_p ++;
	backLog[backLog_p] = 0;
	//backLog_p ++;
	assert(backLog_p < 32000);

	if(backLog_p > 5){
		int writeLen = backLog_p;
		int writePtr = 0;
		while (writeLen > writePtr){
			int len = write(cs, &backLog[writePtr], writeLen - writePtr);

			if (len < 0) {
				log(stream, "Write failed (errno=%d)", errno);
				break;
			} else if (len == 0)
				break;

			writePtr += len;
		}
	}
	backLog[backLog_p-1] = 0;
	log(stream, "http %s", &backLog[4]);

	// Send back an "ok\n" to the server that we are done.
	ret = write(cs, "ok\n", 3);
	if (ret < 3)
		log(stream, "Error: Cannot write to command socket.");

	close(cs);

	/* We do this check now right at the beginning of the connection!
	// Nagios check connections
	if(!strncmp(peerName, "hi.tech.org", 11) || !strncmp(peerIP, "149.20.53.171", 13)){
		if (myDumper){
			pcap_dump_close(myDumper);
			remove(dumpFile);
		}

		fclose(stream);
		remove(logFile);

		return;
	}
	*/

	if (myDumper){
		pcap_dump_close(myDumper);

		// Compress dumped trace
		FILE *infile = fopen(dumpFile, "rb");
		if (infile){
			char gzdumpFile[503];
			snprintf(gzdumpFile, 503, "%s.gz", dumpFile);
			gzFile outfile = gzopen(gzdumpFile, "wb");

			if (outfile){

				log(stream, "Zipping %s to %s", dumpFile, gzdumpFile);

				char inbuffer[128];
				int num_read = 0;
				while ((num_read = fread(inbuffer, 1, sizeof(inbuffer), infile)) > 0) {
					gzwrite(outfile, inbuffer, num_read);
				}
				fclose(infile);
				gzclose(outfile);

				if (remove(dumpFile) != 0)
					perror( "Error deleting file" );
			}
		}
	}

	log(stream, "Done.");
	fclose(stream);
}

void GlasnostReplayer::capturePacket()
{
	/*
    unsigned char pbuffer[65536];
	int size = read(read_socket, pbuffer, sizeof(pbuffer));
	unsigned char *buffer = &pbuffer[14];
	if(size <= 14)
		return;
	size -= 14; // Substract ethernet header
	struct timeval now;
	gettimeofday(&now, NULL);
	*/

	struct pcap_pkthdr *hdr = NULL;
	unsigned char *data;
	int ret = pcap_next_ex(capture, &hdr, (const u_char**)&data);
	if (ret != 1)
		panic("Error while reading a packet from %s (%d)", ethDev.c_str(), ret);

	if (hdr->len < 34)
		panic("Captured packet has only %d bytes, thus cannot be an IP packet", hdr->len);

	unsigned char *buffer = &data[14];
	int size = hdr->len-14;
	struct timeval now = hdr->ts;



	// Only log IP packets
	if ((buffer[0] & 0xF0) == 0x40) {
		unsigned long src, dst;
		memcpy((char *) &src, (char *) &buffer[12], 4);
		memcpy((char *) &dst, (char *) &buffer[16], 4);

		int csize = size;

		// Only log packets from/to the peer
		if (src == peer || dst == peer) {

			int ip_hl = (buffer[0] & 0x0F)*4;
			// If UDP or TCP, strip packet content
			if (buffer[9] == IPPROTO_TCP) {
				csize = ip_hl+((buffer[ip_hl+12] & 0xF0)/4);
				csize += 200;

				// If it is a command packet, log full packet content
				unsigned short src_port, dst_port;
				memcpy((char *) &src_port, (char *) &buffer[ip_hl], 2);
				memcpy((char *) &dst_port, (char *) &buffer[ip_hl+2], 2);

				if ((src_port == htons(commandPort)) || (dst_port == htons(commandPort)))
					csize = size;
			} else if (buffer[9] == IPPROTO_UDP) {
				csize = ip_hl + 8;
				csize += 200;
			}
			if (csize > size)
				csize = size;

			// Anonymize IP header
			if (token != 0) {
				if (src == peer) {
					memcpy((char *) &buffer[12], (char *) &token, 4);
					memset((char *) &buffer[16], 0, 4);
				} else if (dst == peer) {
					memcpy((char *) &buffer[16], (char *) &token, 4);
					memset((char *) &buffer[12], 0, 4);
				}
			}

			struct pcap_pkthdr hdr;
			hdr.ts.tv_sec = now.tv_sec;
			hdr.ts.tv_usec = now.tv_usec;
			hdr.caplen = csize;
			hdr.len = size;
			pcap_dump((u_char*)myDumper, &hdr, buffer);
			//  dumpPacket(buffer, size);

			if (buffer[9] == IPPROTO_TCP) {
				// Check if we saw a RST and cache(?) it.
				//int ip_hl = (buffer[0] & 0x0F)*4;
				if ((src == peer) && ((buffer[ip_hl + 13] & 0x04))) {
					// Got RST!!!
					//log("Got reset from peer!");
					resetsReceived += 1;
				} else if ((dst == peer) && ((buffer[ip_hl + 13] & 0x04))) {
					// Sent RST!!!
					//log("I sent a reset!");
					resetsSent += 1;
				}
			}
		}
	}
}

void GlasnostReplayer::dump(const unsigned char *payload, int len, int indent=0)
{
  int i, off = 0;
  while (off < len) {
    for (int k=0; k<indent; k++)
      fprintf(stream, " ");

    fprintf(stream, "%04X   ", off);
    for (i=0; i<16; i++) {
      if ((i+off) < len)
        fprintf(stream, "%02X ", payload[i+off]);
      else
        fprintf(stream, "   ");
    }

    fprintf(stream, "   ");

    for (i=0; i<16; i++) {
      if ((i+off) < len)
        fprintf(stream, "%c", isprint(payload[i+off]) ? payload[i+off] : '.');
    }

    off += 16;
    fprintf(stream, "\n");
  }
}

/**
 * Sniff packets until the timeout expires or the other socket is ready
 * to be read from.
 *
 * @param sock socket to read from (e.g. a TCP or UDP socket)
 * @param captureSocket (Raw) socket to sniff packets from
 * @param tend The end time of sniffing
 * @param peer address of the peer packets should be sniffed from
 *
 * @returns 0 if sock is ready to be read from or 1 if timeout seconds passed
 */
int GlasnostReplayer::sniffPackets(int sock, int captureSocket, const struct timeval *tend, int peer)
{
	assert((sock >= 0) || (captureSocket >= 0));

	struct timeval now, tv;

	if (tend != NULL)
		calcTimeout(tend, &tv);

	if ((tv.tv_sec == 0) && (tv.tv_usec == 0))
		return 1;

	while(true){

		fd_set fdr;
		FD_ZERO(&fdr);
		if (captureSocket >= 0)
			FD_SET(captureSocket, &fdr);
		if (sock >= 0)
			FD_SET(sock, &fdr);

		int sel = MAX(captureSocket, sock);
		int numSel = 0;

		/* Call select. If we're interrupted in the middle (signal etc.), we continue.
           TODO: Examine errno and panic if appropriate (to prevent spinning) */
		do {
			numSel = select(sel+1, &fdr, NULL, NULL, &tv);
			if (numSel < 0) {
				error(stream, "Select failed (errno=%d)", errno);
				return 1;
			}
		} while (false);

		// Timeout
		if (numSel == 0)
			return 1;

		if (captureSocket >= 0){
			if (FD_ISSET(captureSocket, &fdr)){
				capturePacket();

				// Adjust timeout if set
				if (tend != NULL){
					gettimeofday(&now, NULL);
					tv.tv_sec = tend->tv_sec - now.tv_sec;
					tv.tv_usec = tend->tv_usec - now.tv_usec;
					if (tv.tv_usec < 0){
						tv.tv_usec += 1000000;
						tv.tv_sec -= 1;
					}
					if (tv.tv_sec < 0){
						tv.tv_sec = 0;
						tv.tv_usec = 0;
					}
				}
			}
		}
		if (sock >= 0){
			if (FD_ISSET(sock, &fdr))
				break;
		}
	}
	return 0;
}

int GlasnostReplayer::sniffPacketsForWrite(int sock, int captureSocket, const struct timeval *tend, int peer){

	assert(sock >= 0 || captureSocket >= 0);

	struct timeval now, tv;

	if(tend != NULL)
		calcTimeout(tend, &tv);

	if((tv.tv_sec == 0) && (tv.tv_usec == 0))
		return 1;

	while(true){

		fd_set fdr, fdw;
		FD_ZERO(&fdr);
		FD_ZERO(&fdw);
		if(captureSocket >= 0)
			FD_SET(captureSocket, &fdr);
		if(sock >= 0)
			FD_SET(sock, &fdw);

		int sel = MAX(captureSocket, sock);
		int numSel = 0;

		/* Call select. If we're interrupted in the middle (signal etc.), we continue.
           TODO: Examine errno and panic if appropriate (to prevent spinning) */
		do {
			numSel = select(sel+1, &fdr, &fdw, NULL, &tv);
			if (numSel < 0) {
				error(stream, "Select failed (errno=%d)", errno);
				return 1;
			}
		} while (false);

		// Timeout
		if(numSel == 0){
			return 1;
		}

		if(captureSocket >= 0){
			if(FD_ISSET(captureSocket, &fdr)){
				capturePacket();

				// Adjust timeout if set
				if(tend != NULL){
					gettimeofday(&now, NULL);
					tv.tv_sec = tend->tv_sec - now.tv_sec;
					tv.tv_usec = tend->tv_usec - now.tv_usec;
					if(tv.tv_usec < 0){
						tv.tv_usec += 1000000;
						tv.tv_sec -= 1;
					}
					if(tv.tv_sec < 0){
						tv.tv_sec = 0;
						tv.tv_usec = 0;
					}
				}
			}
		}
		if(sock >= 0){
			if(FD_ISSET(sock, &fdw))
				break;
		}
	}
	return 0;
}


/* 
   read a line and replace the first occurrence of '\r' or '\n' with the string delimiter '\0'
*/

bool GlasnostReplayer::getline(char** buf, size_t* bufsize, FILE *infile, int *lineno)
{
  while (true) {
    if (::getline(buf, bufsize, infile) == -1)
      return false;

    if(lineno != NULL)
    	*lineno ++;

    char *c = *buf;
    while (*c && (*c!='\r') && (*c!='\n'))
      c++;

    *c = 0;
    if (**buf) {
      break;
    } else {
      // empty line, go on reading
    }
  }

  return true;
}


int GlasnostReplayer::writePacket(int sock, unsigned char *data, int size, long long endTime)
{
	int wptr = 0;
	while (wptr < size) {

		long long now = getTimeMicros();
		if (now >= endTime) {
		  log(stream, "Time is up, ending");		  
		  return wptr;
		}

		/* Prepare the bitfields for select(). We always want to read packets from the raw socket
		   (so that we can dump them to the pcap trace), and we almost always want to read data,
		   except if our buffer is full. We only want to write if we have something to send. */

		fd_set fdr, fdw, fdx;
		int maxSocket = 0;
		FD_ZERO(&fdr);
		FD_ZERO(&fdw);
		FD_ZERO(&fdx);

		if (readSocket > 0){
			FD_SET(readSocket, &fdr);
			if (readSocket > maxSocket)
				maxSocket = readSocket;
		}

		FD_SET(sock, &fdw);
		FD_SET(sock, &fdx);
		if (sock > maxSocket)
			maxSocket = sock;

		/* Calculate the timeout value */
		struct timeval tv;
		tv.tv_sec = (int)((endTime-now) / 1000000LL);
		tv.tv_usec = (int)((endTime-now) % 1000000LL);

		int ret = select(sock+1, &fdr, &fdw, &fdx, &tv);
		if (ret < 0)
			panic("writePacket: select() failed (%s)", strerror(errno));

		if (!ret) {
		  log(stream, "Time is up, ending (select() timed out)");
		  return wptr;
		}

		if ((readSocket > 0) && FD_ISSET(readSocket, &fdr)) {
			capturePacket();
		}

		if (FD_ISSET(sock, &fdw)) {
			int w = write(sock, &data[wptr], size-wptr);
			if (w<0) {
				if (errno == ECONNRESET) {
					error(stream, "writePacket: Connection reset\n");
					break;
				}
				if (errno == EPIPE) {
					error(stream, "writePacket: Broken pipe\n");
					break;
				}

				error(stream, "writePacket: Cannot write (%s)", strerror(errno));
				if (wptr == 0)
					return -1;
			}
			else if (w == 0)
				break;

			wptr += w;
			debug(stream, "==wrote %d/%d", wptr, size);
		}

		if (FD_ISSET(sock, &fdx)){
			if (wptr == 0)
				return -1;

			break;
		}
	}
	return wptr;
}

int GlasnostReplayer::readPacket(int sock, unsigned char *data, int size, long long endTime)
{
	int rptr = 0;
	while (rptr < size) {

		long long now = getTimeMicros();
		if (now >= endTime) {
		  log(stream, "Time is up, ending");
		  return rptr;
		}

		/* Prepare the bitfields for select(). We always want to read packets from the raw socket
       (so that we can dump them to the pcap trace), and we almost always want to read data,
       except if our buffer is full. We only want to write if we have something to send. */

		fd_set fdr, fdx;
		int maxSocket = 0;
		FD_ZERO(&fdr);
		FD_ZERO(&fdx);

		if (readSocket > 0){
			FD_SET(readSocket, &fdr);
			if (readSocket > maxSocket)
				maxSocket = readSocket;
		}

		FD_SET(sock, &fdr);
		FD_SET(sock, &fdx);
		if (sock > maxSocket)
			maxSocket = sock;

		/* Calculate the timeout value */
		struct timeval tv;
		tv.tv_sec = (int)((endTime-now) / 1000000LL);
		tv.tv_usec = (int)((endTime-now) % 1000000LL);

		int ret = select(sock+1, &fdr, NULL, &fdx, &tv);
		if (ret < 0)
			panic("readPacket: select() failed (%s)", strerror(errno));

		if (!ret) {
		  log(stream, "Time is up, ending (select() timed out)");
		  return rptr;
		}

		if ((readSocket > 0) && FD_ISSET(readSocket, &fdr)) {
			capturePacket();
		}

		if (FD_ISSET(sock, &fdr)) {

			int maxread = size-rptr;
			if (maxread > 2048)
				maxread = 2048;
			int r = read(sock, &data[rptr], maxread);
			if (r<0) {
				if (errno == ECONNRESET){
					error(stream, "readPacket: Connection reset\n");
					break;
				}
				if (errno == EPIPE) {
					error(stream, "readPacket: Broken pipe\n");
					break;
				}

				error(stream, "readPacket: Cannot read (%s)", strerror(errno));
				if(rptr == 0)
					return -1;
			}
			else if (r == 0)
				break;

			rptr += r;
			debug(stream, "==read %d/%d", rptr, size);
		}

		if (FD_ISSET(sock, &fdx)){
			if(rptr == 0)
				return -1;

			break;
		}
	}

	return rptr;
}


size_t GlasnostReplayer::curlWriteDataCallback(void *buffer, size_t size, size_t nmemb, void *userp) {
  FILE* target_file = (FILE*) userp;
  int bytes_written = fwrite(buffer, size, nmemb, target_file) * size;
  return bytes_written;
}

/**
 * If the script named in scriptUrl does not exist yet in directory dir,
 * fetch it from given Url.
 *
 * Returns the path to the script file.
 * If the file could not be fetched (e.g. HTTP server answered with 'Not Found'), an empty string is returned
 */
string GlasnostReplayer::fetchScriptFile(string scriptUrl, string dir) {

	assert(scriptUrl.length() > 0);
	if(!checkUrl(scriptUrl))
		return "";

	// extract file name from URL
	string fileName;
	string strippedUrl; // URL without http://

	size_t pos = scriptUrl.find("://");
	if(pos != scriptUrl.npos){
	  strippedUrl = scriptUrl.substr(pos+3); // Remove http://
	} else {
	  strippedUrl = scriptUrl;
	}

	pos = strippedUrl.rfind('/');
	if(pos == strippedUrl.npos) { // URL has no slash character, does not file name but just domain name

		pos = fileName.find("?");
		if(pos != fileName.npos)
			fileName = strippedUrl.substr(pos); // Remove everything that's a domain name
		else
			fileName = strippedUrl;

	} else {
		// filename is what comes after last slash character
		fileName = strippedUrl.substr(pos+1);
	}

	pos = fileName.find("?");
	if(pos != fileName.npos){
		if(pos == 0){ // There is no filename, just parameters
			pos = fileName.find("id=");
			if(pos != fileName.npos){
				size_t pos2 = fileName.find('&', pos);
				if(pos2 == fileName.npos)
					fileName = fileName.substr(pos+3);
				else
					fileName = fileName.substr(pos+3, (pos2-pos-3));
			} else {
				error(stream, "Cannot find id parameter while extracting filename. Giving up.");
			}
		} else {
			fileName = fileName.substr(0, pos);
		}
		debug(stream, "Sanitized filename: %s", fileName.c_str());
	}

	log(stream, "fetching URL %s", scriptUrl.c_str());

	string filePath = dir + '/' + fileName;
	log(stream, "checking file %s", filePath.c_str());

	if (!access(filePath.c_str(), F_OK)) {
		log(stream, "file %s exists, using local copy", filePath.c_str());
		return filePath;
	}

	log(stream, "File %s does not exist, fetching from %s", filePath.c_str(), scriptUrl.c_str());
	FILE* newfile = fopen(filePath.c_str(), "w");
	if (newfile == NULL) {
		perror("fopen");
		panic("could not open local file %s for writing", filePath.c_str());
	}


	CURL* curlHandle = curl_easy_init();
	if (curlHandle == NULL) {
		panic("curl_easy_init() failed: could not initialize CURL handle");
	}

	char curlErrorBuffer[CURL_ERROR_SIZE];
	//curl_easy_setopt(curlHandle, CURLOPT_VERBOSE, 1); // only for debugging/testing!
	//char* urlEncodedString = curl_easy_escape(curlHandle, scriptUrl.c_str(), 0);
	//curl_easy_setopt(curlHandle, CURLOPT_URL, urlEncodedString);
	//curl_free(urlEncodedString);
	//log(stream, "url after encoding: %s", urlEncodedString);
	curl_easy_setopt(curlHandle, CURLOPT_URL, scriptUrl.c_str());
	curl_easy_setopt(curlHandle, CURLOPT_ERRORBUFFER, curlErrorBuffer);
	curl_easy_setopt(curlHandle, CURLOPT_WRITEFUNCTION, curlWriteDataCallback);
	curl_easy_setopt(curlHandle, CURLOPT_WRITEDATA, newfile);
	curl_easy_setopt(curlHandle, CURLOPT_NOSIGNAL, 1); // to be set in multi-threaded programs

	//HTTP options
	curl_easy_setopt(curlHandle, CURLOPT_FOLLOWLOCATION, 1); // enable HTTP redirections
	curl_easy_setopt(curlHandle, CURLOPT_MAXREDIRS, -1); // change value to limit the maximum number of allowed redirections (-1 = unbounded)

	if (curl_easy_perform(curlHandle)) {
		error(stream, "curl_easy_perform() failed: %s", curlErrorBuffer);
		curl_easy_cleanup(curlHandle);
		return "";
	}

	fclose(newfile);

	long errCode;
	curl_easy_getinfo(curlHandle, CURLINFO_RESPONSE_CODE, &errCode);
	debug(stream, "Response code: %ld", errCode);


	// handling error codes
	// check if we are using http
	if (scriptUrl.substr(0, 4) == "http") {

	  // checking HTTP error code
	  switch (errCode) {
	  case 404:
	    // HTTP: Not Found
	    // remove empty file
	    log(stream, "HTTP returned error code %ld (Not Found)", errCode);
	    if (remove(filePath.c_str()) < 0) {
	      perror("remove()");
	      error(stream, "Unable to remove file %s", filePath.c_str());
	    }
	    curl_easy_cleanup(curlHandle);
	    return "";

	  default:
	    break;
	  }
	}

	curl_easy_cleanup(curlHandle);
	return filePath;
}


bool GlasnostReplayer::readAndWritePacket(int sock, unsigned char *obuf, int *o_size, unsigned char *ibuf, int *i_size, long long endTime){
	int wptr = 0, rptr = 0;
	while ((wptr < *o_size) && (rptr < *i_size)) {

		long long now = getTimeMicros();
		if (now >= endTime){
			*o_size = wptr;
			*i_size = rptr;
			log(stream, "Time is up, ending");
			return false;
		}

		/* Prepare the bitfields for select(). We always want to read packets from the raw socket
		   (so that we can dump them to the pcap trace), and we almost always want to read data,
		   except if our buffer is full. We only want to write if we have something to send. */

		fd_set fdr, fdw, fdx;
		int maxSocket = 0;
		FD_ZERO(&fdr);
		FD_ZERO(&fdw);
		FD_ZERO(&fdx);

		if (readSocket > 0){
			FD_SET(readSocket, &fdr);
			if (readSocket > maxSocket)
				maxSocket = readSocket;
		}

		FD_SET(sock, &fdw);
		FD_SET(sock, &fdr);
		FD_SET(sock, &fdx);
		if (sock > maxSocket)
			maxSocket = sock;

		/* Calculate the timeout value */
		struct timeval tv;
		tv.tv_sec = (int)((endTime-now) / 1000000LL);
		tv.tv_usec = (int)((endTime-now) % 1000000LL);

		int ret = select(sock+1, &fdr, &fdw, &fdx, &tv);
		if (ret < 0)
			panic("writePacket: select() failed (%s)", strerror(errno));

		if (!ret) {
			*o_size = wptr;
			*i_size = rptr;
			log(stream, "Time is up, ending (select() timed out)");
			return false;
		}

		if ((readSocket > 0) && FD_ISSET(readSocket, &fdr)) {
			capturePacket();
		}

		if (FD_ISSET(sock, &fdr) && (rptr < *i_size)) {

			int maxread = *i_size-rptr;
			if (maxread > 2048)
				maxread = 2048;
			int r = read(sock, &ibuf[rptr], maxread);
			if (r<0) {
				if (errno == ECONNRESET){
					error(stream, "readPacket: Connection reset\n");
					break;
				}
				if (errno == EPIPE) {
					error(stream, "readPacket: Broken pipe\n");
					break;
				}

				error(stream, "readPacket: Cannot read (%s)", strerror(errno));
				if(rptr == 0) {
					*o_size = wptr;
					*i_size = rptr;
					return false;
				}
			}
			else if (r == 0)
				break;

			rptr += r;
			debug(stream, "==read %d/%d", rptr, *i_size);
		}

		if (FD_ISSET(sock, &fdw) && (wptr < *o_size)) {
			int w = write(sock, &obuf[wptr], *o_size-wptr);
			if (w<0) {
				if (errno == ECONNRESET) {
					error(stream, "writePacket: Connection reset\n");
					break;
				}
				if (errno == EPIPE) {
					error(stream, "writePacket: Broken pipe\n");
					break;
				}

				error(stream, "writePacket: Cannot write (%s)", strerror(errno));
				if (wptr == 0) {
					*o_size = wptr;
					*i_size = rptr;
					return false;
				}
			}
			else if (w == 0)
				break;

			wptr += w;
			debug(stream, "==wrote %d/%d", wptr, *o_size);
		}


		if (FD_ISSET(sock, &fdx)){
			if ((wptr == 0) && (rptr == 0)){
				*o_size = wptr;
				*i_size = rptr;
				return false;
			}

			break;
		}
	}
	*o_size = wptr;
	*i_size = rptr;
	return true;
}



void GlasnostReplayer::createMessage(string& buf, std::vector<GlasnostParser::PayloadElement> payload, unsigned char* prevmsg, unsigned int prevmsg_size)
{
  buf.clear();
  unsigned int offset, len, low, high, temp;
  uint32_t val;
  using namespace GlasnostParser;

  for (unsigned int i = 0; i < payload.size(); ++i) {

    PayloadElement& ple = payload[i];
    switch (ple.type) {

    case PayloadElement::DATA:
      buf.append(ple.data);
      break;

    case PayloadElement::PREV_MSG:
      // TODO: what happens if the previous message does not have enough bytes at the given offset?
      offset = ple.n;
      len = ple.k;
      if (offset+len > prevmsg_size) {
	// offset + len exceeds the size of previous message's buffer
	error(stream, "Size of previous message exceeded, truncating message (size=%d, offset=%u, len=%u)", prevmsg_size, offset, len);      
	len = prevmsg_size - offset;
      }            
      if (prevmsg_size > offset)
	buf.append((char*) (prevmsg+offset), len);
      break;

    case PayloadElement::REPEAT:
      val = ple.n;
      len = ple.k;
      buf.append(len, val);
      break;

    case PayloadElement::RANDOM:
      len = ple.n;
      for (temp = 0; temp < len; ++temp) {
	buf.append(1, random()%256);
      }
      break;

    case PayloadElement::RANDINT:      
      low = ple.n;
      high = ple.k;      
      assert(integer_length == 4);      
      val = htonl(low+(random()%(high-low+1)));
      for (temp = 0; temp < integer_length; ++temp) {
	buf.append(1, ((char*) &val)[temp]);
      }
      break;
    }
  }  
}


bool GlasnostReplayer::warmUpSocket(int sock, int direction, int durationSec){

	if(sock == -1){
		error(stream, "Socket not connected, cannot warm-up socket.");
		return false;
	}

	reset();

	struct timeval tend;
	gettimeofday(&tend, NULL);
	tend.tv_sec = tend.tv_sec + durationSec;
	bool isTerminated = false;

	if(direction == DOWNSTREAM){
		char buffer[4096];

		while(!isTerminated){

			gettimeofday(&tend, NULL);
			tend.tv_sec = tend.tv_sec + durationSec;

			if(sniffPackets(sock, readSocket, &tend, peer) == 1)
				break;

			int ret = read(sock, buffer, sizeof(buffer));
			if(ret == -1){
				log(stream, "warmupSocket: Cannot read from socket: %d", errno);
				if(bytesReceived <= 0)
					return false;
				isTerminated = 1;
				break;
			}
			if(ret == 0)
				break;

			bytesReceived += ret;
		}

		return true;
	} else if(direction == UPSTREAM){
		char buffer[16000];
		srand(tend.tv_sec);

		while(!isTerminated){

			for(unsigned int i=0; i<sizeof(buffer); i++)
				buffer[i] = (char) rand();

			if(sniffPacketsForWrite(sock, readSocket, &tend, peer) == 1)
				break;

			int ret = write(sock, buffer, sizeof(buffer));
			if(ret < 0 /* && errno != EAGAIN */){
				log(stream, "warmupSocket: Cannot write to socket: %d", errno);
				if(bytesTransmitted <= 0)
					return false;
				isTerminated = 1;
				break;
			}
			if(ret == 0)
				break;

			bytesTransmitted += ret;
		}
		return true;
	} else {
		error(stream, "warmupSocket: Unknown direction: %d", direction);
		return false;
	}
}


/**
 * Run a transfer between client and server. The protocol to use is retrieved from the
 * script file.
 */

bool GlasnostReplayer::runTransfer(int sock, const string& protocol, int durationSec, bool isServer, struct timeval *start, struct timeval *end, bool sendControlFlow)
{
	if(sock == -1){
		error(stream, "Socket not connected, cannot run test.");
		gettimeofday(start, NULL);
		end->tv_sec = start->tv_sec;
		end->tv_usec = start->tv_usec;
		return false;
	}

	log(stream, "Replaying %s for %d seconds", protocol.c_str(), durationSec);

	// Buffers for sending and receiving messages
	const int bufSize = 11*2048576;
	// input buffer
	unsigned char* last_received_message = (unsigned char*) malloc(bufSize);
	int last_received_message_length = 0;

	if (!last_received_message)
	  panic("Out of memory");
	// output buffer
	//obuf = (unsigned char*) malloc(bufSize);
	//if (!obuf)
	//	panic("Out of memory");

	string message_payload;	

	// Init
	gettimeofday(start, NULL);
	long long now = getTimeMicros();
	long long endTime = now + (durationSec * 1000000LL);       // expected end of transfer
	long long lastPacket = now;
	struct timeval pause;
	pause.tv_sec = 0; pause.tv_usec = 0;

	reset();
	bool startMeasuring = false;
	bool protocolError = false;

	// Make sure that there are scripts ready for replay
	if(protocolScript.empty()){
	  vector<string> unknown;
	  readInScript(protocols, unknown);
	}
	assert(!protocolScript.empty());
	if(protocolScript.empty() || (protocolScript.find(protocol) == protocolScript.end())){
	  snprintf(error_msg, 200, "Protocol %s unknown", protocol.c_str());
	  error(stream, "Protocol %s unknown", protocol.c_str());
	  return false;
	}

	using namespace GlasnostParser;
	const GlasnostScript& script = protocolScript.find(protocol)->second;
	unsigned int next_command_index = 0;
	while (next_command_index < script.commands.size()) {

	  const GlasnostCommand* curr_com = script.commands[next_command_index];

	  log(stream, "Executing command %d of %zu", next_command_index, script.commands.size());

	  if (curr_com->type == SEND) {

	    const SendCommand* sc = (const SendCommand*) curr_com;

	    bool weSend = false;
	    if (sc->endpoint == CLIENT)
	      weSend = !isServer;
	    else 
	      weSend = isServer;
	    
	    // Just calculates the packet size to speed things up for the control flow (random bytes in payload)
	    if(weSend && sendControlFlow) {

	      message_payload.clear();
	      for (int i = 0; i < sc->length; ++i) 
		message_payload.append(1, random()%256);

	    } else if (weSend) {
	      // Question: why do we create a message even when we do not have to send? (i.e. weSend=false)
	      createMessage(message_payload, sc->payload, last_received_message, last_received_message_length);	      
	    }
	    
	    now = getTimeMicros();
	    if (now >= endTime) {
	      log(stream, "Time is up, ending");
	      break;
	    }		    
	    
	    // Honor spacing between packets while sending
	    if ((pause.tv_sec > 0) || (pause.tv_usec > 0)) {
	      
	      //debug(stream, "sleeping for %ld.%ld seconds", pause.tv_sec, pause.tv_usec/1000);
	      
	      //pause.tv_sec += (int)(now / 1000000LL);
				//pause.tv_usec += (int)(now % 1000000LL);
	      
				// Or add spacing to timing of last sent packet?
	      pause.tv_sec += (int)(lastPacket / 1000000LL);
	      pause.tv_usec += (int)(lastPacket % 1000000LL);
	      
	      while (pause.tv_usec > 1000000) {
		pause.tv_sec += 1;
		pause.tv_usec -= 1000000;
	      }
	      
	      sniffPackets(-1, readSocket, &pause, peer);
	      pause.tv_sec = 0; pause.tv_usec = 0;
	    }

	    if (startMeasuring) {
	      gettimeofday(start, NULL);
	      bytesTransmitted = 0;
	      bytesReceived = 0;
	      startMeasuring = false;
	    }

	    if (weSend) {
	      log(stream, "Sending %zu bytes", message_payload.length());
	      //DEBUG
	      //log(stream, "SENDING:\n%s", message_payload.c_str());
	      //for (unsigned int i = 0; i < message_payload.length(); ++i)
	      //	fprintf(stream, "%x ", (unsigned char) message_payload[i]); 
	      //fprintf(stream, "\n");

	      int w = writePacket(sock, (unsigned char*) message_payload.c_str(), message_payload.length(), endTime);
	      
	      if (w < 0) { // Error
		log(stream, "writePacket failed");
		break;
	      } else if ((w >= 0) && ((unsigned int) w < message_payload.length())) { // Timeout or socket closed in the middle
		bytesTransmitted += w;
		log(stream, "writePacket did not write all bytes (%d/%zu)", w, message_payload.length());
		break;
	      }
	      
	      lastPacket = getTimeMicros();
	      bytesTransmitted += w;
	      lastState = next_command_index;
	
	    } else {
	      log(stream, "Receiving %d bytes", sc->length);

	      if (sc->length > bufSize) {
		panic("Length of message to be received exceeds receiver buffer size! (length=%u, buffersize=%d)", sc->length, bufSize);
	      }
	      
	      int r = readPacket(sock, last_received_message, sc->length, endTime);	      
	      //DEBUG	      
	      //string temps;
	      //if (r > 0)
	      //	for (int i= 0; i < r; ++i) 		
	      //	  temps.append(1, last_received_message[i]);
	      //log(stream, "RECEIVED:\n%s", temps.c_str());

	      if (r < 0) { // Error
		log(stream, "readPacket failed");
		break;
	      } else if ((r >= 0) && r < sc->length) { // Timeout or socket closed in the middle (OR somebody in the middle messing with the content!!! Transparency?)
		bytesReceived += r;
		log(stream, "readPacket did not read all bytes (%d/%d)", r , sc->length);
		break;
	      }
	      
	      last_received_message_length = r;
	      
	      // PROBLEM: Some packets have random content we can not check against
	      //if (!hasRandomParts && !buffersHaveSameContent(ibuf, obuf, r)) {
	      //	error(stream, "Packet received does not match expected packet.");
	      //	protocolError = true;
	      //	break;
	      //}
	      
	      lastPacket = getTimeMicros();
	      bytesReceived += r;
	      lastState = next_command_index;	
	    }
	    
	    next_command_index++;
	    
	  } else if (curr_com->type == PAUSE) {

	    const PauseCommand* pc = (PauseCommand*) curr_com;
	    bool weSend = false;
	    if (pc->endpoint == CLIENT)
	      weSend = !isServer;
	    else
	      weSend = isServer;
	    	    
	    
	    if(weSend){	    
	      pause.tv_sec = pc->sec;
	      pause.tv_usec = pc->usec;
	      log(stream, "pausing for %ld msec", (long int)(pc->sec*1000 + (pc->usec/1000.0)));
	    } 
	    next_command_index++;

	  } else if (curr_com->type == GOTO) {
	    
	    const GotoCommand* gtc = (GotoCommand*) curr_com;
	    log(stream, "Goto command: jumping to command %d", gtc->target_command);
	    next_command_index = gtc->target_command;

	  } else if (curr_com->type == START_MEASURING) {
	    
	    log(stream, "Start measuring command");
	    startMeasuring = true;
	    next_command_index++;
	  }

	  now = getTimeMicros();
	  if (now >= endTime) {
	    log(stream, "Time is up, ending");
	    break;
	  }
 	  
	}

	lastState = next_command_index;
	gettimeofday(end, NULL);

	/* End of the main loop. We could have reached this point in several ways: The connection
     could have timed out (yippie!), it could have been interrupted by the ISP (gotcha!),
     or we could have run into a protocol error (bummer!) */

	log(stream, "End of transfer; %.0f bytes transferred and %.0f bytes received", bytesTransmitted, bytesReceived);

	/* We can't return immediately because we might otherwise miss the RST from the other
     side. To ensure the RST makes it to the pcap trace, we spend two additional seconds
     capturing packets. */

	//log2("Spending an additional two seconds sniffing packets");
	struct timeval tv;
	gettimeofday(&tv, NULL);
	tv.tv_sec += 1;
	//tv.tv_usec += 500000;
	sniffPackets(-1, readSocket, &tv, peer);

	log(stream, "Resets received: %d ; Resets sent: %d", resetsReceived, resetsSent);

	free(last_received_message);

	return (!protocolError && ((bytesTransmitted + bytesReceived) > 0));
}


#if 0
// Only for testing!
void usage()
{
	panic("Usage: glasnost_replayer [-p <commandPort>] [-i ethDev] [-d logDirectory] [-scriptdir scriptFilesDirectory] -s protocolScriptFile");
}


int main(int argc, char *args[]){

	if (argc > 9) {
		usage();
	}

	int command_port = 19971;
	char eth_dev[200];
	char log_dir[200];
	char script_file[200];
	string script_dir = "."; // directory used to store temporary test script files

	strcpy(eth_dev, "eth1");
	strcpy(log_dir, ".");
	memset(script_file, 0, sizeof(script_file));

	for (int i = 1; i < argc; i++) {
		if (!strcmp(args[i], "-p")) {
			i++;
			if (i >= argc)
				usage();
			command_port = atoi(args[i]);
		} else if (!strcmp(args[i], "-i")) {
			i++;
			if (i >= argc)
				usage();
			strcpy(eth_dev, args[i]);
		} else if (!strcmp(args[i], "-d")) {
			i++;
			if (i >= argc)
				usage();
			strncpy(log_dir, args[i], sizeof(log_dir));
		} else if (!strcmp(args[i], "-s")) {
			i++;
			if (i >= argc)
				usage();
			strncpy(script_file, args[i], sizeof(script_file));
		} else if (!strcmp(args[i], "-scriptdir")) {
		  i++;
		  if (i >= argc)
		    usage();
		  script_dir = string(args[i]);
		} else {
			fprintf(stderr, "Unknown option: %s\n", args[i]);
			usage();
		}
	}

	if(strlen(script_file) <= 0)
		usage();

	int command_sock; // TCP socket to receive commands on
	if ((command_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		panic("Cannot create socket\n");

	int on = 1;
	setsockopt(command_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	// Bind to the given port
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(command_port);

	if (bind(command_sock, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
		perror("Error");
		panic("bind() command socket failed.");
	}


#if 0

	// CURL TEST
	if (curl_global_init(CURL_GLOBAL_ALL)) {
	  panic("curl_global_init() failed: couldn't initialize curl library");
	}

	GlasnostReplayer *gr = new GlasnostReplayer(command_sock);
	gr->setInterface(eth_dev);
	gr->setLogDirectory(log_dir);
	gr->setScriptDir(script_dir);
	//gr->testFetchScriptFile(script_file);

	//gr->setScriptFile(script_file);
	//gr->run();

	close(command_sock);

	curl_global_cleanup();
	return 0;
	//END OF CURL TEST
#endif

	// Set it to listen
	if (listen(command_sock, 1) < 0)
		panic("listen() on command socket failed\n");

	// Accept the incoming connection
	struct sockaddr_in from;
	int len = sizeof(from);
	int cs = accept(command_sock, (struct sockaddr*)&from, (socklen_t*)&len);
	if (cs < 0)
		panic("Cannot accept new connection: %d", errno);


	if (curl_global_init(CURL_GLOBAL_ALL)) {
	  panic("curl_global_init() failed: couldn't initialize curl library");
	}

	GlasnostReplayer *gr = new GlasnostReplayer(cs);
	gr->setInterface(eth_dev);
	gr->setLogDirectory(log_dir);
	gr->setScriptDir(script_dir);
	gr->setScriptFile(script_file);

	gr->run();

	close(command_sock);

	curl_global_cleanup();
}

#endif
