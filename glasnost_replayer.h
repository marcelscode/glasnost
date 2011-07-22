#ifndef BLOCKING_DETECTOR_H_
#define BLOCKING_DETECTOR_H_

#include <map>
#include <pcap.h>
#include <string>
#include <vector>
#include <curl/curl.h>
#include "glasnost_parser.h"

using namespace std;


class GlasnostReplayer {

private:
	int openRawSocket(const string device);
	bool runTransfer(int sock, const string& protocol, int durationSec, bool isServer, struct timeval *start, struct timeval *end, bool sendControlFlow);
	bool warmUpSocket(int sock, int direction, int durationSec);
	void capturePacket();
	int writePacket(int sock, unsigned char *data, int size, long long endTime);
	int readPacket(int sock, unsigned char *data, int size, long long endTime);
	bool readAndWritePacket(int sock, unsigned char *obuf, int *oSize, unsigned char *ibuf, int *iSize, long long endTime);
	int nextMessageLength(char **arg, int len, int ip, const char *protocol);
	//void createMessage(char **arg, int len, unsigned char *buf, unsigned int *bufLen, int ip, const char *protocol);
	void createMessage(string& buf, std::vector<GlasnostParser::PayloadElement> payload, unsigned char* prevmsg, unsigned int prevmsg_size);

	int sniffPackets(int sock, int readSocket, const struct timeval *tend, int peer);
	int sniffPacketsForWrite(int sock, int captureSocket, const struct timeval *tend, int peer);
	void dump(const unsigned char *payload, int len, int indent);

	bool checkUrl(string url);
	static size_t curlWriteDataCallback(void *buffer, size_t size, size_t nmemb, void *userp);
	string fetchScriptFile(string url, string dir=".");

	bool getline(char**buf, size_t* bufsize, FILE *infile, int *lineno);
	bool readInScript(const vector<string> &proto, vector<string> &unknownProtocol);
	char* getProtocol(char *line);
	bool buffersHaveSameContent(const char *payload1, const char *payload2, int len){
		for(int i=0; i<len; i++){
			if(payload1[i] != payload2[i])
				return false;
		}
		return true;
	}

	void cleanupAndExit(){
		close(cs);
		if (stream != stdout)
			fclose(stream);
		exit(0);
	}

	void reset(){
		resetsSent = 0;
		resetsReceived = 0;
		lastState = -1;
		bytesTransmitted = 0;
		bytesReceived = 0;
	}

	/**
	 * Remove leading and trailing whitespace (including tabs)
	 */
	void trim(char *line) {
		unsigned int len = strlen(line);

		while(len > 0){
			if((line[len-1] == ' ') || (line[len-1] == '\t')){
				line[len-1] = 0;
				len--;
			} else
				break;
		}

		unsigned int offset = 0;

		while(offset < len){
			if((line[offset] == ' ') || (line[offset] == '\t'))
				offset++;
			else
				break;
		}

		if(offset != 0){
			for(unsigned int i=0; i<len-offset; i++)
				line[i] = line[i+offset];
			for(unsigned int i=len-offset; i<len; i++)
				line[i] = 0;
		}
	}


	struct ltstr {
	  bool operator()(const char* s1, const char* s2) const {
	    return strcmp(s1, s2) < 0;
	  }
	};

	pcap_dumper_t *myDumper;
	pcap_t *capture;
	int readSocket;

	FILE *stream;

	int cs;
	int commandPort;

	int ports[2];
	string ethDev, logDir, scriptFile, scriptDir;
	vector<string> protocols;
	//map<const char*, vector<string>*, ltstr> protocolScript;
	GlasnostParser::ProtocolScript protocolScript;

	unsigned long peer;

	///unsigned char *ibuf, *obuf;

	int resetsSent, resetsReceived;
	int lastState;
	double bytesTransmitted, bytesReceived;

	char error_msg[200];

public:
	GlasnostReplayer(int cs);
	~GlasnostReplayer();
	void run();


	void setPorts(int bad_port, int good_port){
		ports[0] = bad_port;
		ports[1] = good_port;
	}

	void setInterface(const string dev){
		ethDev = dev;
	}
	void setLogDirectory(const string dir){
		logDir = dir;
	}
	void setScriptFile(const string file){
		scriptFile = file;
	}
	void setScriptDir(const string dir) {
		scriptDir = dir;
	}

	// Only for testing!
	string testFetchScriptFile(string url, string dir="."){
		return fetchScriptFile(url, dir);
	}

};

#endif /* BLOCKING_DETECTOR_H_ */
