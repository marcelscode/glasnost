/*
 * This http server serves multiple purposes
 *
 * 1. Fetch Glasnost test
 *    Requires GET parameters retrieve=script + id=X for the test with the unique ID X
 *    The script of the test is returned if found or a HTTP error is returned.
 *
 * 2. Send Glasnost jar archives
 *    If the URL requested equals GlasnostReplayer.jar or GlasnostReplayerMac.jar
 *    the server returns these jar archives
 *
 * 3. Send log/dump files from a Glasnost test run
 *    Requires GET parameters retrieve=dump or retrieve=log + id, ip, and hostname that are
 *    associated with a test run
 *
 * 4. Glasnost result proxy to work-around Internet Explorer limitation
 *    Requires GET parameters id, ip, hostname, and server that are associated with a test run
 *
 * TODO Log which IP connected to this server
 *
 */

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <curl/curl.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string>
#include <microhttpd.h>
#include "glasnost_parser.h"
#include <fstream>
#include <iomanip>
#include "tools.h"

using namespace std;

extern string logDir, scriptDir;

static const char *htmlResultsHeader = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\n<html>\n<head><title>Results are ready.</title></head>\n<body onload=\"document.rform.submit();\"><h1>Your results are ready</h1>\n<p>If you are not redirected automatically, please click the button below.</p>\n";
static const char *htmlTrailer = "</body>\n</html>\n";
//static const char *errorPage = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html>\n<head><title>Error</title></head>\n<body>\n<h1>Error</h1>\n<p>An error occurred while processing your request.</p>\n</body>\n</html>\n";
static const char *errorPage400 = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html>\n<head><title>400 Bad Request</title></head>\n<body>\n<h1>Bad Request</h1>\n<p>The URL you requested is not valid.</p>\n</body>\n</html>\n";
static const char *errorPage404 = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html>\n<head><title>404 Not Found</title></head>\n<body>\n<h1>Not Found</h1>\n<p>The requested URL was not found on this server.</p>\n</body>\n</html>\n";
static const char *errorPage500 = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html>\n<head><title>500 Internal Server Error</title></head>\n<body>\n<h1>Internal Server Error</h1>\n<p>There was an internal server error while processing your request.</p>\n</body>\n</html>\n";

#define GlasnostJar "GlasnostReplayer.jar"
#define GlasnostMacJar "GlasnostReplayerMac.jar"



FILE *stream = stdout;

/**
 * Check URL whether it is OK to download
 */
bool checkUrl(string url)
{
	// TODO  
  return true;
}

size_t curlWriteDataCallback(void *buffer, size_t size, size_t nmemb, void *userp) {
  FILE* target_file = (FILE*) userp;
  int bytes_written = fwrite(buffer, size, nmemb, target_file) * size;
  return bytes_written;
}

/**
 * If the script named in scriptUrl does not exist yet in directory dir,
 * fetch it from given Url.
 * If preferID is true (default), the filename will be taken from the id= parameter in the URL (if present) instead of the real filename.
 *
 * Returns the path to the script file.
 * If the file could not be fetched (e.g. HTTP server answered with 'Not Found'), an empty string is returned
 *  
 */
string fetchRemoteFile(string scriptUrl, string dir, bool preferID = true) {

	assert(scriptUrl.length() > 0);
	if(!checkUrl(scriptUrl))
		return "";

	// extract file name from URL	
	string strippedUrl; // URL without http:// preamble
	string fileName;
	
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
		if((pos == 0) || (preferID && (fileName.find("id=") != fileName.npos))){ // There is no filename, just parameters
			pos = fileName.find("id=");
			if(pos != fileName.npos){
				size_t pos2 = fileName.find('&', pos);
				if(pos2 == fileName.npos)
					fileName = fileName.substr(pos+3);
				else
					fileName = fileName.substr(pos+3, (pos2-pos-3));
			} else {
				error(stderr, "Cannot find id parameter while extracting filename. Giving up.");
			}
		} else {
			fileName = fileName.substr(0, pos);
		}
		debug(stdout, "Sanitized filename: %s", fileName.c_str());
	}

	log(stdout, "fetching URL %s", scriptUrl.c_str());

	string filePath = dir + '/' + fileName;
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
		error(stderr, "curl_easy_perform() failed: %s", curlErrorBuffer);
		curl_easy_cleanup(curlHandle);
		return "";
	}

	fclose(newfile);

	long errCode;
	curl_easy_getinfo(curlHandle, CURLINFO_RESPONSE_CODE, &errCode);
	debug(stdout, "Response code: %ld", errCode);


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
	      error(stderr, "Unable to remove file %s", filePath.c_str());
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


MHD_Result sendFile(struct MHD_Connection *connection, const char *file) {

	MHD_Result ret;
	struct MHD_Response *response;

	log(stdout, "Request to send back file '%s'", file);

	// Q Maybe cache jar files for increased performance?
	//if((strncmp(file, GlasnostJar, strlen(GlasnostJar)) == 0) || (strncmp(file, GlasnostMacJar, strlen(GlasnostMacJar)) == 0)){

	struct stat fileStatus;
	if(stat(file, &fileStatus) != 0){
		perror("could not stat");
		error(stderr, "File missing or not accessible: %s", file);
		response = MHD_create_response_from_data(strlen(errorPage404), (void*) errorPage404, MHD_NO, MHD_NO);
		ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
		MHD_destroy_response(response);
		return ret;
	}

	debug(stdout, "Found file %s with size %d\n", file, (int) fileStatus.st_size);

	unsigned int bufSize = fileStatus.st_size;
	char *buffer = (char *) malloc(bufSize);
	if(buffer == NULL){
		error(stderr, "FATAL: Was not able to allocate %u bytes.", bufSize);
		response = MHD_create_response_from_data(strlen(errorPage500), (void*) errorPage500, MHD_NO, MHD_NO);
		ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
		MHD_destroy_response(response);
		return ret;
	}
	memset(buffer, 0, bufSize);

	FILE *ffile = fopen(file, "r");
	if(ffile){
		unsigned int n = fread(buffer, 1, bufSize, ffile);
		if(n != (unsigned int) bufSize){
			error(stderr, "Read in %d bytes, but was supposed to read in %d bytes.", n, bufSize);
			response = MHD_create_response_from_data(strlen(errorPage500), (void*) errorPage500, MHD_NO, MHD_NO);
			ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
			MHD_destroy_response(response);
			return ret;
		}
	} else{
		error(stderr, "File missing or not accessible: %s", file);
		response = MHD_create_response_from_data(strlen(errorPage404), (void*) errorPage404, MHD_NO, MHD_NO);
		ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
		MHD_destroy_response(response);
		return ret;
	}
	fclose(ffile);

	debug(stdout, "Sending back file to client: %d bytes", bufSize);
	response = MHD_create_response_from_data(bufSize, (void*) buffer, MHD_YES, MHD_NO);

	unsigned int size = strlen(file);
	if((size > 4) && (file[size-4] == '.') && (file[size-3] == 'j') && (file[size-2] == 'a') && (file[size-1] == 'r')){
		debug(stdout, "Declaring this file as a jar archive");
		MHD_add_response_header (response, "Content-Type", "application/java-archive");
	} else{
		string f = file;
		size_t lastSlash = f.rfind('/');

		if(lastSlash != f.npos) {
			// filename is what comes after last slash character
			f = "attachment; filename=" + f.substr(lastSlash+1);
		} else {
			f = "attachment; filename=" + f;
		}

		MHD_add_response_header (response, "Content-Disposition", f.c_str());
		debug(stdout, "Adding http header Content-Disposition: %s", f.c_str());
	}

	ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);
	return ret;
}

#if 0
// old version: serves the file in source format
// serve a script with the given id
MHD_Result fetchTest(struct MHD_Connection *connection, const char *id) {

	MHD_Result ret;
	struct MHD_Response *response;

	// Now, we have to sanitize id, check that id has only hex-decimal characters
	for(unsigned int i=0; i<strlen(id); i++){
		if(! isxdigit(id[i])){
			error(stderr, "ID contains invalid characters: %s", id);
			response = MHD_create_response_from_data(strlen(errorPage400), (void*) errorPage400, MHD_NO, MHD_NO);
			ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
			MHD_destroy_response(response);
			return ret;
		}
	}

	// Use the ID to find the script file the user is interested on
	char fname[500];
	snprintf(fname, sizeof(fname), "%s/%s", scriptDir.c_str(), id);

	log(stdout, "Client requested script file %s", fname);

	struct stat fileStatus;
	if(stat(fname, &fileStatus) != 0){
		log(stdout, "Script file missing or not accessible: '%s'. Trying to fetch it from somewhere else.", fname);

		string fetchedFile = fetchRemoteFile("http://broadband.mpi-sws.org/transparency/glasnost.php?findtest&id="+string(id), scriptDir.c_str());

		if(fetchedFile.compare("") == 0){
			error(stderr, "Failed to fetch test with ID %s. Giving up.", id);
			response = MHD_create_response_from_data(strlen(errorPage404), (void*) errorPage404, MHD_NO, MHD_NO);
			ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
			MHD_destroy_response(response);
			return ret;
		}

		log(stdout, "Successfully retrieved script file from remote server: %s", fetchedFile.c_str());
		strncpy(fname, fetchedFile.c_str(), sizeof(fname)); // Copy new filename
		stat(fname, &fileStatus);
	}

	unsigned int bufSize = fileStatus.st_size;
	char *buffer = (char *) malloc(bufSize);
	if(buffer == NULL){
		error(stderr, "FATAL: Was not able to allocate %u bytes.", bufSize);
		response = MHD_create_response_from_data(strlen(errorPage500), (void*) errorPage500, MHD_NO, MHD_NO);
		ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
		MHD_destroy_response(response);
		return ret;
	}
	memset(buffer, 0, bufSize);

	FILE *fscript = fopen(fname, "r");
	if(fscript){
		unsigned int n = fread(buffer, 1, bufSize, fscript);
		if(n != bufSize){
			error(stderr, "Read in %d bytes, but was supposed to read in %d bytes.", n, bufSize);
			response = MHD_create_response_from_data(strlen(errorPage500), (void*) errorPage500, MHD_NO, MHD_NO);
			ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
			MHD_destroy_response(response);
			return ret;
		}
	} else{
		error(stderr, "Script file missing or not accessible: %s", fname);
		response = MHD_create_response_from_data(strlen(errorPage404), (void*) errorPage404, MHD_NO, MHD_NO);
		ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
		MHD_destroy_response(response);
		return ret;
	}
	fclose(fscript);

	response = MHD_create_response_from_data(bufSize, (void*) buffer, MHD_YES, MHD_NO);	
	MHD_add_response_header (response, "Content-Type", "text/plain");
	ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);
	return ret;
}
#endif

// serve a script with the given id
// new version: serves the compact representation of the parsed script
MHD_Result fetchTest(struct MHD_Connection *connection, const char *id, bool recursiveSearch = false, bool doSerialize = true) {

	MHD_Result ret;
	struct MHD_Response *response;

	// Now, we have to sanitize id, check that id has only hex-decimal characters
	for(unsigned int i=0; i<strlen(id); i++){
		if(! isxdigit(id[i])){
			error(stderr, "ID contains invalid characters: %s", id);
			response = MHD_create_response_from_data(strlen(errorPage400), (void*) errorPage400, MHD_NO, MHD_NO);
			ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
			MHD_destroy_response(response);
			return ret;
		}
	}

	// Use the ID to find the script file the user is interested on
	char fname[500];
	snprintf(fname, sizeof(fname), "%s/%s", scriptDir.c_str(), id);

	log(stdout, "Client requested script file %s", fname);

	struct stat fileStatus;
	if(stat(fname, &fileStatus) != 0){

		// Attention: Do not try to perform a recursive search if we got contacted from the load balances (thus a recursive search is already taking place)
		if(!recursiveSearch){
			log(stdout, "Script file missing or not accessible: '%s'. Sending back 404.", fname);
			response = MHD_create_response_from_data(strlen(errorPage404), (void*) errorPage404, MHD_NO, MHD_NO);
			ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
			MHD_destroy_response(response);
			return ret;
		}

		log(stdout, "Script file missing or not accessible: '%s'. Trying to fetch it from somewhere else.", fname);

		string fetchedFile = fetchRemoteFile("http://broadband.mpi-sws.org/transparency/glasnost.php?findtest&serialize=0&id="+string(id), scriptDir.c_str());

		if(fetchedFile.compare("") == 0){
			error(stderr, "Failed to fetch test with ID %s. Giving up.", id);
			response = MHD_create_response_from_data(strlen(errorPage404), (void*) errorPage404, MHD_NO, MHD_NO);
			ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
			MHD_destroy_response(response);
			return ret;
		}

		log(stdout, "Successfully retrieved script file from remote server: %s", fetchedFile.c_str());
		strncpy(fname, fetchedFile.c_str(), sizeof(fname)); // Copy new filename
		stat(fname, &fileStatus);
	}

	//unsigned int bufSize = fileStatus.st_size;
	//char *buffer = (char *) malloc(bufSize);
	//if(buffer == NULL){
	//error(stderr, "FATAL: Was not able to allocate %u bytes.", bufSize);
	//response = MHD_create_response_from_data(strlen(errorPage500), (void*) errorPage500, MHD_NO, MHD_NO);
	//ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
	//MHD_destroy_response(response);
	//return ret;
	//}
	//memset(buffer, 0, bufSize);

	ifstream ifs(fname);
	GlasnostParser::ProtocolScript pscript;
	if(ifs.is_open()) {
	  //unsigned int n = fread(buffer, 1, bufSize, fscript);

	  log(stdout, "Parsing script file %s", fname);
	  string errorMsg;
	  if (!GlasnostParser::parseScript(ifs, pscript, errorMsg)) {	  
	    error(stderr, "Error while parsing protocol file %s:\n%s", fname, errorMsg.c_str());
	    response = MHD_create_response_from_data(strlen(errorPage500), (void*) errorPage500, MHD_NO, MHD_NO);
	    ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);	    
	    MHD_destroy_response(response);

	    ifs.close();
	    remove(fname); // remove broken test configuration

	    return ret;
	  }
	  
	  //if(n != bufSize){
	  //	error(stderr, "Read in %d bytes, but was supposed to read in %d bytes.", n, bufSize);
	  //	response = MHD_create_response_from_data(strlen(errorPage500), (void*) errorPage500, MHD_NO, MHD_NO);
	  //	ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
	  //	MHD_destroy_response(response);
	  //	return ret;
	  //}
	} else{
		error(stderr, "Script file missing or not accessible: %s", fname);
		response = MHD_create_response_from_data(strlen(errorPage404), (void*) errorPage404, MHD_NO, MHD_NO);
		ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
		MHD_destroy_response(response);
		return ret;
	}

	ifs.close();

	log(stdout, "File %s is valid", fname);

	string serialized_protocols;
	if(doSerialize) {
		// now we serialize all the found protocols and send them back to the client
		serialized_protocols.append(intToStr((unsigned int) pscript.size()));
		serialized_protocols.append(1, ':');
		for (GlasnostParser::ProtocolScript::iterator i = pscript.begin(); i != pscript.end(); ++i) {

		  i->second.serialize(serialized_protocols);
		  //cout << "protocol " << i->first << " port1=" << i->second.port1 << " port2=" << i->second.port2 << " with " << i->second.commands.size() << " commands\n";
		  //for (unsigned int n = 0; n < i->second.commands.size(); ++n)
		  // cout << n + 1 << ": " << *(i->second.commands[n]) << endl;
		  serialized_protocols.append(1, ':');
		}
		GlasnostParser::freeProtocolScript(pscript);
		log(stdout, "Sending %zu serialized test scripts to the client", pscript.size());
	} else {
		GlasnostParser::freeProtocolScript(pscript);

		ifstream ifs(fname); // We have to re-open the file as otherwise seeking fails
		if(ifs.is_open()) {
			// get length of file:
			ifs.seekg(0, ios::end);
			streampos flength = ifs.tellg();
			char *fbuffer = new char[flength];
			ifs.seekg(0, ios::beg);
			ifs.read(fbuffer, flength);
			ifs.close();

			serialized_protocols = string(fbuffer, flength);
			delete[] fbuffer;

			log(stdout, "Sending test scripts to the client");
		} else{
			error(stderr, "Script file missing or not accessible: %s", fname);
			response = MHD_create_response_from_data(strlen(errorPage404), (void*) errorPage404, MHD_NO, MHD_NO);
			ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
			MHD_destroy_response(response);
			return ret;
		}
	}
	
	//DEBUG
	//for (unsigned int i =0; i < serialized_protocols.size(); ++i) 
	// printf("%x ", (unsigned char) serialized_protocols[i]);
	//printf("\n");
	//cout << serialized_protocols << endl;

	response = MHD_create_response_from_data(serialized_protocols.length(), (void*) serialized_protocols.c_str(), MHD_NO, MHD_YES);	
	MHD_add_response_header (response, "Content-Type", "text/plain");
	ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);

	return ret;
}


bool getline(char *buf, int bufsize, FILE *infile) {
  while (true) {
    if (!fgets(buf, bufsize, infile))
      return false;

    char *c = buf;
    while (*c && (*c!='\r') && (*c!='\n'))
      c++;

    *c = 0;
    if (buf[0])
      break;
  }

  return true;
}


MHD_Result proxyTestResultPage(struct MHD_Connection *connection, const char *id, const char *ip, const char *hostname, const char *nextPage) {

	// - Use ID, IP, and Hostname to find the log file of the test run
	// - Parse the log file and read in the parameters
	// - Create a web page with a HTTP POST form and a hidden form with all the parameters.
	//    Add JScript that immediately submits the form to the server
	//    Add a button, say that the results are ready and that the user should click the button

	MHD_Result ret;
	struct MHD_Response *response;
	string fname = logDir + "/glasnost_" + ip + '_' + hostname + '_' + id + ".log";

	debug(stderr, "Looking for file %s to generate result page proxy page\n", fname.c_str());

	char read_buf[100000];
	char server_log[100000];
	char client_log[100000];
	memset(server_log, 0, sizeof(server_log));
	memset(client_log, 0, sizeof(client_log));

	char page[100000];
	int page_p = 0;

	FILE *flog = fopen(fname.c_str(), "r");
	if(flog != NULL){
		while(getline(read_buf, sizeof(read_buf), flog)){
			// First 10 characters are Unix timestamp
			if(strncmp((const char *) &read_buf[14], "Client: http ", 13) == 0){
				strncpy(client_log, (const char *) &read_buf[27], sizeof(client_log));

			} else if(strncmp((const char *) &read_buf[14], "http ", 5) == 0){
				strncpy(server_log, (const char *) &read_buf[19], sizeof(server_log));
			}

			if((strlen(server_log) > 0) && (strlen(client_log) > 0))
				break;
		}
		fclose(flog);
	}

	if((flog == NULL) || (strlen(server_log) == 0) || (strlen(client_log) == 0)){

		if(flog == NULL)
			error(stderr, "Log file missing or not accessible: %s", fname.c_str());
		else
			error(stderr, "Log data missing (%zu %zu).\n", strlen(server_log), strlen(client_log));

		response = MHD_create_response_from_data(strlen(errorPage404), (void*) errorPage404, MHD_NO, MHD_NO);

		const char *server = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "server");

		if(strncmp(nextPage, "http://", 7) == 0)
			snprintf(page, sizeof(page), "%s?error=3&peer=%s&id=%s&server=%s&hostname=%s&msg=Results%%20not%%20found%%20on%%20server", nextPage, ip, id, server, hostname);
		else
			snprintf(page, sizeof(page), "http://%s?error=3&peer=%s&id=%s&server=%s&hostname=%s&msg=Results%%20not%%20found%%20on%%20server", nextPage, ip, id, server, hostname);
		MHD_add_response_header(response, "Location", page);
		ret = MHD_queue_response(connection, MHD_HTTP_SEE_OTHER, response);
		MHD_destroy_response(response);
		return ret;
	}


	if(strncmp(nextPage, "http://", 7) == 0)
		page_p += snprintf(&page[page_p], sizeof(page), "%s<form method=\"post\" action=\"%s\" name=\"rform\">\n", htmlResultsHeader, nextPage);
	else
		page_p += snprintf(&page[page_p], sizeof(page), "%s<form method=\"post\" action=\"http://%s\" name=\"rform\">\n", htmlResultsHeader, nextPage);

	// Now slice up the elements and put each in a HTML form element
	char *a, *b, *c;
	char *tok, *tok2;
	a = strtok_r(client_log, "&", &tok);
	while(a != NULL){
		b = strtok_r(a, "=", &tok2);
		c = strtok_r(NULL, "=", &tok2);
		if((b != NULL) && (c != NULL))
			page_p += snprintf(&page[page_p], sizeof(page), "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n", b, c);
		else
			error(stderr, "Cannot parse: %s", a);

		a = strtok_r(NULL, "&", &tok);
	}

	a = strtok_r(server_log, "&", &tok);
	while(a != NULL){
		b = strtok_r(a, "=", &tok2);
		c = strtok_r(NULL, "=", &tok2);
		if((b != NULL) && (c != NULL))
			page_p += snprintf(&page[page_p], sizeof(page), "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n", b, c);
		else
			error(stderr, "Cannot parse: %s", a);

		a = strtok_r(NULL, "&", &tok);
	}


	page_p += snprintf(&page[page_p], sizeof(page), "<input type=\"submit\" value=\"Display results\">\n</form>\n%s", htmlTrailer);

	if(page_p == sizeof(page))
		error(stderr, "Page might be truncated.");

	response = MHD_create_response_from_data(strlen(page), (void*) page, MHD_NO, MHD_YES);
	ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);
	return ret;
}

static MHD_Result answerToConnection(void * cls, struct MHD_Connection * connection,
		const char * url, const char * method, const char * version,
		const char * upload_data, size_t * upload_data_size, void ** ptr) {

	if (strcmp(method, "GET") != 0)
		return MHD_NO; // unexpected method

	debug(stdout, "URL: %s", url);

	// If the Glasnost jar archive was requested, send it back
	if(strcmp(url, "/GlasnostReplayer.jar") == 0)
		return sendFile(connection, "GlasnostReplayer.jar");
	else if(strcmp(url, "/GlasnostReplayerMac.jar") == 0)
		return sendFile(connection, "GlasnostReplayerMac.jar");
	else if(strcmp(url, "/BlockingDetector.jar") == 0)
		return sendFile(connection, "BlockingDetector.jar");
	else if(strcmp(url, "/BlockingDetectorMac.jar") == 0)
		return sendFile(connection, "BlockingDetectorMac.jar");

	// Get HTTP GET values and find out what the client wants
	const char *retrieve = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "retrieve");
	const char *s_recursive = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "recursive");
	const char *s_serialized = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "serialize");

	bool recursiveSearch = false;
	if((s_recursive != NULL) && (!strncmp(s_recursive, "1", 1) || !strncmp(s_recursive, "yes", 3) || !strncmp(s_recursive, "true", 4)))
		recursiveSearch = true;

	bool doSerialize = true;
	if((s_serialized != NULL) && (!strncmp(s_serialized, "0", 1) || !strncmp(s_serialized, "no", 2) || !strncmp(s_serialized, "false", 5)))
		doSerialize = false;


	if(retrieve != NULL){

		const char *id = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "id");

		if((id != NULL) && (strcmp(retrieve, "script") == 0))
			return fetchTest(connection, id, recursiveSearch, doSerialize);

		const char *ip = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "ip");
		const char *hostname = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "hostname");

		if((id != NULL) && (ip != NULL) && (hostname != NULL)){
			string fname;
			if(strcmp(retrieve, "log") == 0)
				fname = logDir + "/glasnost_" + ip + '_' + hostname + '_' + id + ".log";
			else if(strcmp(retrieve, "dump") == 0)
				fname = logDir + "/glasnost_" + ip + '_' + hostname + '_' + id + ".dump.gz";

			if(fname.length() > 0)
				return sendFile(connection, fname.c_str());
		}
	}

	const char *id = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "id");
	const char *ip = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "ip");
	const char *hostname = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "hostname");
	const char *nextPage = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "nextPage");

	if((id != NULL) && (ip != NULL) && (hostname != NULL) && (nextPage != NULL))
		return proxyTestResultPage(connection, id, ip, hostname, nextPage);


	error(stderr, "Unknown request: %s", url);
	struct MHD_Response *response = MHD_create_response_from_data(strlen(errorPage400), (void*) errorPage400, MHD_NO, MHD_NO);
	MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
	MHD_destroy_response(response);
	return ret;
}

struct MHD_Daemon* startupHttpDaemon(int port){
	if(port <= 0)
		return NULL;

	struct MHD_Daemon *d = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION, port, NULL,
			NULL, &answerToConnection, NULL, MHD_OPTION_CONNECTION_TIMEOUT, 5, MHD_OPTION_END);

	if (d == NULL)
		error(stderr, "Cannot start http daemon.");

	return d;
}

#if 0
string scriptDir, logDir;
int main(int argc, char **argv) {

	if ((argc < 2) || (argc > 4))
		panic("%s <port> [scriptDir [logDir]]", argv[0]);

	if(argc >= 3)
		scriptDir = argv[2];
	else
		scriptDir = ".";

	if(argc >= 4)
			logDir = argv[2];
		else
			logDir = ".";

	struct MHD_Daemon *d = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION, atoi(argv[1]), NULL,
			NULL, &answerToConnection, NULL, MHD_OPTION_CONNECTION_TIMEOUT, 5, MHD_OPTION_END);

	if (d == NULL){
		panic("Cannot start http daemon.");
	}

	while(1){sleep(86400);}

	return 0;
}
#endif
