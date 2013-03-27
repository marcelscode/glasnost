/**
 * Process running on the measurement server
 *
 * TODO Add a watchdog for http_server if necessary
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "tools.h"
#include "glasnost_replayer.h"

using namespace std;

#define VERSION "10.05.2010"
#define MAX_CONCURRENT_CONNECTIONS 9
#define CHILD_TIMEOUT 1200 // in seconds

#define HTTPport 19981

int commandPort = 19970;
string ethDev, logDir, scriptFile, scriptDir;

pid_t childPid[MAX_CONCURRENT_CONNECTIONS];
long int childStarttime[MAX_CONCURRENT_CONNECTIONS];

extern struct MHD_Daemon* startupHttpDaemon(int port);

/**
 * What parameter main() takes.
 */
void usage() {
	panic("Usage: gserver [-p <commandPort>] [-i ethDev] [-d logDirectory] [-scriptdir scriptFilesDirectory] -s protocolScriptFile");
}

// Cleaning up
void child_handler(int sig)
{
	pid_t pid;
	//for(int i=0; i<MAX_CONCURRENT_CONNECTIONS; i++){
	while (1) {
		pid = waitpid((pid_t) -1, NULL, WNOHANG); // Do not block here!

		if (pid < 0) {
			//mprintf("%lld Wait for child failed: %d\n", (getTimeMicros()/1000LL), errno);
			// Currently, there are no more children waiting for cleanup
			return;
		} else if (pid == 0)
			return;
		else {
			for (int i = 0; i < MAX_CONCURRENT_CONNECTIONS; i++) {
				if (childPid[i] == pid) {
					childPid[i] = 0;
					mprintf("%lld Process %d has finished.\n", (getTimeMicros()/1000LL), i);
					break;
				}
			}
		}
	}
}

/**
 * Check whether we can serve another client
 * @return -1 if no slot is available, proc_num otherwise
 */
int get_next_proc_num()
{
	child_handler(0); // Cleanup

	for (int i = 0; i < MAX_CONCURRENT_CONNECTIONS; i++) {
		if(childPid[i] == 0)
			return i;
	}

	// All slots are taken, but check whether any of the children ran for too long
	struct timeval tv;
	gettimeofday(&tv, NULL);

	bool killed = false;
	for (int i = 0; i < MAX_CONCURRENT_CONNECTIONS; i++) {
		if ((childStarttime[i] + CHILD_TIMEOUT) < tv.tv_sec) {
			mprintf("%lld Killing child #%d as it ran for %d seconds.\n", (getTimeMicros()/1000LL), i, tv.tv_sec - childStarttime[i]);
			kill(childPid[i], SIGTERM);
			killed = true;
		}
	}

	// If we have killed a process, try to clean up and find an available slot
	if (killed) {
		child_handler(0);
		for (int i = 0; i < MAX_CONCURRENT_CONNECTIONS; i++) {
			if (childPid[i] == 0)
				return i;
		}
	}

	return -1;
}

int main(int argc, char *args[])
{
	if (argc > 9) {
		usage();
	}

	ethDev = "eth0";
	logDir = ".";
	scriptDir = ".";
	scriptFile = "";

	for (int i = 1; i < argc; i++) {
		if (!strcmp(args[i], "-p")) {
			i++;
			if (i >= argc)
				usage();
			commandPort = atoi(args[i]);
		} else if (!strcmp(args[i], "-i")) {
			i++;
			if (i >= argc)
				usage();
			ethDev = args[i];
		} else if (!strcmp(args[i], "-d")) {
			i++;
			if (i >= argc)
				usage();
			logDir = args[i];
		} else if (!strcmp(args[i], "-s")) {
			i++;
			if (i >= argc)
				usage();
			scriptFile = args[i];
		} else if (!strcmp(args[i], "-scriptdir")) {
		  i++;
		  if (i >= argc)
		    usage();
		  scriptDir = args[i];
		} else {
			fprintf(stderr, "Unknown option: %s\n", args[i]);
			usage();
		}
	}

	if (scriptFile.length() <= 0) {
		fprintf(stderr, "You have to specify the protocol script file!\n");
		usage();
	} else if (access(scriptFile.c_str(), R_OK)) {
		fprintf(stderr, "Protocol script file '%s' not found.\n", scriptFile.c_str());
		usage();
	}

	mprintf("Starting gserver (Version: %s)\n", VERSION);
	mprintf("Configuration: -p %d -i %s -d %s -scriptdir %s\n", commandPort, ethDev.c_str(), logDir.c_str(), scriptDir.c_str());

	struct stat f_stat;
	if (stat(logDir.c_str(), &f_stat) != 0)
		panic("Cannot access '%s'. Does this directory exist?", logDir.c_str());
	if (!S_ISDIR(f_stat.st_mode))
		panic("'%s' is not a directory. Please create it or adjust the -d parameter.", logDir.c_str());

	if (stat(scriptDir.c_str(), &f_stat) != 0)
		panic("Cannot access '%s'. Does this directory exist?", scriptDir.c_str());
	if (!S_ISDIR(f_stat.st_mode))
		panic("'%s' is not a directory. Please create it or adjust the -scriptdir parameter.", scriptDir.c_str());


	if (curl_global_init(CURL_GLOBAL_ALL)) {
	  panic("curl_global_init() failed: couldn't initialize curl library");
	}


	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, child_handler);

	for (int i = 0; i < MAX_CONCURRENT_CONNECTIONS; i++) {
		childPid[i] = 0;
	}

	// Start test fetcher webserver
	struct MHD_Daemon *httpd = startupHttpDaemon(HTTPport);
	if(httpd == NULL)
		panic("Failed to start HTTP test fetcher daemon.");
	else
		mprintf("HTTP test fetcher daemon running.\n");

	// Get command socket
	int commandSock; // TCP socket to receive commands on
	if ((commandSock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		panic("Cannot create socket");

	int on = 1;
	setsockopt(commandSock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	/* Bind to the given port */
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(commandPort);

	if (bind(commandSock, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
		perror("Error");
		panic("bind() command socket failed.");
	}

	/* Set it to listen */
	if (listen(commandSock, (MAX_CONCURRENT_CONNECTIONS*2)) < 0)
		panic("listen() on command socket failed\n");

	while (1) {

		/* Accept the incoming connection */
		struct sockaddr_in from;
		int len = sizeof(from);
		int cs = accept(commandSock, (struct sockaddr*)&from, (socklen_t*)&len);
		if (cs < 0)
			panic("Cannot accept new connection: %d", errno);

		// Select next process number
		int nextProcNum = get_next_proc_num();

		// MAX concurrent connection reached. Tell client that this server is busy.
		if (nextProcNum == -1) {

			mprintf("%lld Telling %d.%d.%d.%d that I am busy.\n", (getTimeMicros()/1000LL), from.sin_addr.s_addr&0xFF, (from.sin_addr.s_addr>>8)&0xFF, (from.sin_addr.s_addr>>16)&0xFF, (from.sin_addr.s_addr>>24)&0xFF);
			char buf[64];
			snprintf(buf, 64, "busy %d.%d.%d.%d \n", from.sin_addr.s_addr&0xFF, (from.sin_addr.s_addr>>8)&0xFF, (from.sin_addr.s_addr>>16)&0xFF, (from.sin_addr.s_addr>>24)&0xFF);

			int ret = write(cs, buf, strlen(buf));
			if(ret < 5){
				mprintf("%lld Cannot write 'busy' to command socket.\n", (getTimeMicros()/1000LL));
			}
			close(cs);
		} else {

			pid_t child = fork();
			if (child == 0) {
				//close(command_sock);

				GlasnostReplayer *gr = new GlasnostReplayer(cs);
				gr->setInterface(ethDev);
				gr->setLogDirectory(logDir);
				gr->setScriptDir(scriptDir);
				gr->setScriptFile(scriptFile);
				gr->run();
				exit(0);
			} else if (child == -1) {
				mprintf("%lld Cannot fork new process: %d\n", (getTimeMicros() / 1000LL), errno);
			} else {
				childPid[nextProcNum] = child;
				struct timeval tv;
				gettimeofday(&tv, NULL);
				childStarttime[nextProcNum] = tv.tv_sec; // precision in seconds is just fine
				close(cs);
			}
		}
	}

	close(commandSock);
	curl_global_cleanup();

	mprintf("gserver: finished.\n");
}
