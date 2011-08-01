#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include "glasnost_parser.h"
#include "tools.h"
#include <arpa/inet.h>
#include <limits.h>

using namespace std;


unsigned int GlasnostParser::max_err_line_len = 200; // never ouput more than so many characters of a script line reporting an error
unsigned int GlasnostParser::max_payload_size = 1000000000; // maximum size of a payload

unsigned int GlasnostParser::integer_length = 4; // bytes in an integer

void GlasnostParser::GlasnostScript::free_memory()
{
  //cerr << "FREEING " << commands.size() << " com\n";

  for (unsigned int i = 0; i < commands.size(); ++i)
    delete commands[i];
}


void GlasnostParser::GlasnostScript::serialize(string& buf)
{
  buf.append("PROTO:" + protocol + ":PORT1:" + intToStr(port1) + ":PORT2:" + intToStr(port2) + ":DURATION:" + intToStr(duration));

  buf.append(":" + intToStr((unsigned int) commands.size()));
  for (unsigned int c = 0; c < commands.size(); ++c) {
    buf.append(1, ':');
    commands[c]->serialize(buf);
  }
}


void GlasnostParser::SendCommand::serialize(std::string& buf)
{
  buf.append("SEND:");
  if (endpoint == SERVER)
    buf.append("SERVER");
  else
    buf.append("CLIENT");

  buf.append(":" + intToStr((unsigned int) payload.size()));

  for (unsigned int i = 0; i < payload.size(); ++i) {
    buf.append(1, ':');
    payload[i].serialize(buf);
  }
}

void GlasnostParser::PayloadElement::serialize(string& buf)
{
  switch (type) {

  case PREV_MSG:
  case RANDINT:
  case REPEAT:
    if (type == PREV_MSG)
      buf.append("PREVMSG:");
    else if (type == RANDINT)
      buf.append("RANDINT:");
    else
      buf.append("REPEAT:");
    buf.append(intToStr(n) + ":" + intToStr(k));
    break;

  case RANDOM:
    buf.append("RANDOM:");
    buf.append(intToStr(n));
    break;

  case DATA:
    buf.append("DATA:" + intToStr((unsigned int) data.length()) + ":");
    buf.append(data);
    break;
  }

}


void GlasnostParser::GotoCommand::serialize(std::string& buf)
{
  buf.append("GOTO:" + intToStr(target_command));
}

void GlasnostParser::PauseCommand::serialize(std::string& buf)
{
  buf.append("PAUSE:");
  if (endpoint == SERVER)
    buf.append("SERVER");
  else
    buf.append("CLIENT");

  buf.append(":" + intToStr(sec) + ":" + intToStr(usec));
}

void GlasnostParser::StartMeasuringCommand::serialize(std::string& buf)
{
  buf.append("START_MEASURING");
}


string GlasnostParser::make_error(const string& line, const string& message, int errpos, int linenum)
{
  ostringstream oss;

  oss << linenum << endl;

  oss << message << endl;

  oss << "(after character " << errpos+1 << " on the line)" << endl;
  oss << endl;

  if (line.length() > max_err_line_len) {

    int h = max_err_line_len / 2;
    unsigned int from = (h <= errpos ? errpos-h : 0);
    if (from != 0)
      oss << "... ";

    oss << line.substr(from,max_err_line_len) << " ..." << endl;

  } else {
    oss << line << endl;
  }

  return oss.str();
}


void GlasnostParser::SendCommand::append_repeat_payload(unsigned int byte, int repeat)
{
  length += repeat;
  PayloadElement e;
  e.type = PayloadElement::REPEAT;
  e.n = byte;
  e.k = repeat;
  payload.push_back(e);
}

void GlasnostParser::SendCommand::append_data_payload(const string& str)
{
  length += str.size();
  if (!payload.empty()) {
    if (payload.back().type == PayloadElement::DATA) {
      payload.back().data.append(str);
      return;
    }
  }

  PayloadElement e;
  e.type = PayloadElement::DATA;
  e.data = str;
  payload.push_back(e);
}


void GlasnostParser::SendCommand::append_randint_payload(int low, int high)
{
  this->length += integer_length;
  PayloadElement e;
  e.type = PayloadElement::RANDINT;
  e.n = low;
  e.k = high;
  payload.push_back(e);
}

void GlasnostParser::SendCommand::append_random_payload(int length)
{
  this->length += length;
  PayloadElement e;
  e.type = PayloadElement::RANDOM;
  e.n = length;
  payload.push_back(e);
}


void GlasnostParser::SendCommand::append_prevmsg_payload(int offset, int length)
{
  this->length += length;
  PayloadElement e;
  e.type = PayloadElement::PREV_MSG;
  e.n = offset;
  e.k = length;
  payload.push_back(e);
}



bool GlasnostParser::GlasnostScript::resolve_labels(const map<std::string, unsigned int>& label_map, std::string& unresolved)
{
  unresolved.clear();

  for (unsigned int i = 0; i < commands.size(); ++i) {
    if (commands[i]->type == GOTO) {

      GotoCommand* gt = (GotoCommand*) commands[i];
      map<string, unsigned int>::const_iterator lm = label_map.find(gt->label);
      if (lm == label_map.end()) {
	unresolved = gt->label;
	return false;
      }
      gt->target_command = lm->second;
    }
  }

  return true;
}

void GlasnostParser::GlasnostScript::append_command(GlasnostCommand* new_command)
{
  commands.push_back(new_command);
}

bool GlasnostParser::isValidProtocolName(const string& str)
{

  for (string::const_iterator i = str.begin(); i != str.end(); ++i)
    if (!isalnum(*i) && *i != '.' && *i != '_' && *i != '-')
      return false;

  return true;
}


/* 
 *  Compresss whitespaces to one expect for ones enclosed in double quotes
 *  remove all whitespaces before a '(' or within a '(' ')' pair (arguments of commands)
 */
void GlasnostParser::compress_spaces(string& str) {

  //cerr << "STR" << endl << str << endl;

  string::iterator i = str.begin();

  bool in_quote = false;
  bool in_arguments = false;
  while (i != str.end()) {

    if (*i == ' ' || *i == '\t') {

      if (!in_quote) {

	string::const_iterator next = i;
	++next;
	if (*next == ' ' || *next == '\t' || *next == '('
	    || (in_arguments)) {
	  i = str.erase(i);
	  continue;
	} else
	  *i = ' ';
      }

    } else if (*i == '"')
      in_quote = !in_quote;
    else if (*i == '(')
      in_arguments = true;
    else if (*i == ')')
      in_arguments = false;

    ++i;
  }

  //  cerr << "BECAME" << endl << str << endl;

}

void GlasnostParser::freeProtocolScript(ProtocolScript& pscript)
{
  for (ProtocolScript::iterator ps = pscript.begin(); ps != pscript.end(); ++ps)
    ps->second.free_memory();
  pscript.clear();
}


/* 
   parses scriptFile and fills the pscript data structure with all protocols found
   return true if scriptFile is valid, false otherwise
   If scriptFile is invalid, errorMsg is filled with an error message describing the cause

 */

bool GlasnostParser::parseScript(const string& scriptFile, ProtocolScript& pscript, string& errorMsg, bool allow_bundling)
{
  ifstream ifs(scriptFile.c_str());
  if(!ifs.is_open()) {
    errorMsg = string("Could not open script file ") + scriptFile;
    return false;
  }

  bool ret_val = parseScript(ifs, pscript, errorMsg, allow_bundling);

  ifs.close();
  return ret_val;
}


/*
  parses the input file stream ifs and fills the pscript data structure with all protocols found
  return true if file associated with ifs is valid, false otherwise
  If theh file is invalid, errorMsg is filled with an error message describing the cause
  ifs must be open, but it is NOT closed before returning;
*/

bool GlasnostParser::parseScript(ifstream& ifs, ProtocolScript& pscript, string& errorMsg, bool allow_bundling)
{
  unsigned int totalNumLines = 0;
  GlasnostScript current_script;
  SendCommand* current_send_command = 0;
  EndPoint current_endpoint;
  //  int lineNumber = 0;
  string line;
  string thisLine;
  bool valid = false;
  map<string, unsigned int> label_map;
  freeProtocolScript(pscript);

  if (!ifs.is_open()) {
    errorMsg = "input file stream is not open";
    goto parsing_done;
  }

  while(getline(ifs, line)){
    totalNumLines ++;

    trim(line);

    if(line.empty()|| line.substr(0,1) == "#" || line.substr(0,8) ==  "comment ")
      // skip comments and empty lines
      continue;

    thisLine = line;
    int pos = 0;

    //if((strcmp(linebuf, "") == 0) || (strncmp(linebuf, "#", 1) == 0) || (strncmp(linebuf, "comment ", 8) == 0)){
    //} else if((strncmp(linebuf, "[protocol:", 10) == 0) && (linebuf[strlen(linebuf)-1] == ']')){


    if(line.substr(0,10) == "[protocol:" && line[line.length()-1] ==  ']'){

      if (!current_script.protocol.empty()) {
	string label;
	if (!current_script.resolve_labels(label_map, label)) {
	  errorMsg = "Label " + label + " was used but not defined";
	  goto parsing_done;
	}
	if (current_script.commands.empty()) {
	  errorMsg = "Protocol " + current_script.protocol + " does not contain any commands";
	  goto parsing_done;
	}
	pscript.insert(ProtocolScript::value_type(current_script.protocol, current_script));
      }
      current_script = GlasnostScript();
      label_map.clear();

      //if (line.length() > max_script_line_len) {
      //	errorMsg = make_error(thisLine, "Line exceeds maximum length of " + intToStr(max_script_line_len) + " character", pos, totalNumLines);
      //	goto parsing_done;
      //}

      // remove leading and trailing "[]"
      line.erase(line.length()-1,1);
      line.erase(0,1);

      istringstream iss(line);

      while (!iss.eof()) {
	string word;
	iss >> word;
	pos = (unsigned int)(iss.tellg()) - word.size();
	//cerr << "working on " << word << endl;

	if (word.substr(0,9) == "protocol:") {

		size_t colon = word.find_first_of(":");
	  //lineNumber = 0;
	  current_script.protocol = word.substr(colon+1);
	  if (!isValidProtocolName(current_script.protocol)) {
	    errorMsg = make_error(thisLine, "a protocol name can only contain alphanumeric characters and '-_.'", pos, totalNumLines);
	    goto parsing_done;
	  }
	  if (current_script.protocol.find(':') != string::npos) {
	    errorMsg = make_error(thisLine, "a protocol name cannot contain a \":\"", pos, totalNumLines);
	    goto parsing_done;
	  }
	  if (pscript.find(current_script.protocol) != pscript.end()) {
	    errorMsg = make_error(thisLine, string("protocol ") + current_script.protocol + string(" defined more than once"), pos, totalNumLines);
	    goto parsing_done;
	  }
	  if (!pscript.empty() && !allow_bundling) {
	    errorMsg = make_error(thisLine, "you cannot define multiple protocols in the same file", pos, totalNumLines);
	    goto parsing_done;
	  }

	  //cerr << "protocol is " << protocol << endl;

	} else if (word.substr(0,5) == "port:") {

		size_t colon = word.find_first_of(':');
		size_t comma = word.find_first_of(',');

	  int ports = 2;
	  if (comma == string::npos) {
	    ports = 1; // only one port specified
	  }
	  for (int i = 0; i < ports; ++i) {

	    string port_string;

	    if (i == 0)
	      port_string = word.substr(colon+1, comma-colon-1);
	    else
	      port_string = word.substr(comma+1);

	    istringstream port_iss(port_string);
	    int port;
	    port_iss >> port;
	    if (port_iss.fail() || !isDigitString(port_string)) {
	      errorMsg = make_error(thisLine, "Port statement has non-integer parameter", pos+1, totalNumLines);
	      goto parsing_done;
	    }
	    if (port < 0 || port > 65535) {
	      errorMsg = make_error(thisLine, "Port numbers must be between 0 and 65535", pos+1, totalNumLines);
	      goto parsing_done;
	    }
	    if (i == 0)
	      current_script.port1 = port;
	    else
	      current_script.port2 = port;
	  }

	  //cerr << "port1 = " << port1 << endl << "port2 = " << port2 << endl;

	} else if (word.substr(0,9) == "duration:") {

	  size_t colon = word.find_first_of(':');
	  string duration_string(word.substr(colon+1));
	  istringstream duration_iss(duration_string);
	  int duration;
	  duration_iss >> duration;
	  if (duration_iss.fail() || duration < 0 || !isDigitString(duration_string)) {
	    errorMsg = make_error(thisLine, "Duration statement has non-integer parameter", pos+1, totalNumLines);
	    goto parsing_done;
	  }
	  current_script.duration = duration;
	  //cerr << "duration = " << duration << endl;

	} else {
	  errorMsg = make_error(thisLine, "Invalid protocol preamble", pos+1, totalNumLines);
	  goto parsing_done;
	}

      }

    } else { // LINE WITH COMMANDS

      if (current_script.protocol.empty()) {
	errorMsg = make_error(thisLine, "You have to specify a protocol name", pos, totalNumLines);
	goto parsing_done;
      }

      compress_spaces(line);
      //if (line.length() > max_script_line_len) {
      //	errorMsg = make_error(thisLine, "Line exceeds maximum length of " + intToStr(max_script_line_len) + " character", pos, totalNumLines);
      //	goto parsing_done;
      //}

      istringstream iss(line);

      enum { LINENUM, ENDPOINT, ENDPOINT_COMMAND, SEND_PAYLOAD, NOTHING, MEASURING, GOTO_ARGUMENT } expect = ENDPOINT;

      while (!iss.eof()) {

	string word;
	iss >> word;
	//cerr << "FOUND WORD:" << endl << word << endl;

	if (!word.empty()) {

	  pos = (unsigned int)(iss.tellg()) - word.length();

	  if (expect == NOTHING) {

	    errorMsg = make_error(thisLine, "Unknown words after end of command", pos, totalNumLines); //lineNumber);
	    goto parsing_done;

	  } else if (expect == GOTO_ARGUMENT) {

	    //istringstream goto_iss(word);
	    //int goto_line;
	    //goto_iss >> goto_line;
	    //if (goto_line < 1 || !isDigitString(word) || goto_iss.fail()) {
	    // errorMsg = make_error(thisLine, "Goto statement requires a positive integer argument", pos, totalNumLines);//lineNumber);
	    // goto parsing_done;
	    //}

	    current_script.append_command(new GotoCommand(word));

	    expect = NOTHING;

	  } else if (expect == MEASURING) {

	    if (word != "measuring") {
	      errorMsg = make_error(thisLine, "Invalid command", pos, totalNumLines);//, lineNumber);
	      goto parsing_done;
	    }

	    current_script.append_command(new StartMeasuringCommand());

	    expect = NOTHING;

	  } else if (expect == LINENUM) {

	    cerr << "ERROR" << endl;
	    exit(1);

	    //int linenum;
	    //istringstream linenum_string(word);
	    //linenum_string >> linenum;
	    //if (linenum_string.fail() || linenum <=0) {
	    // errorMsg = make_error(thisLine, "Invalid line number (must be a strictly postivie integer)", pos, totalNumLines);
	    // goto parsing_done;
	    //}

	    //if (linenum != lineNumber+1) {
	    // errorMsg = make_error(thisLine, "Invalid line number (must increase by 1 with every new line)", pos, totalNumLines);
	    // goto parsing_done;
	    //}

	    //lineNumber = linenum;

	    expect = ENDPOINT;

	} else if (expect == ENDPOINT) {

	    //if (word == "end") {

	    // current_script.append_command(new EndCommand());

	    // expect = NOTHING;

	    //	      if (!current_script.protocol.empty()) {
	    //	string label;
	    //	if (!current_script.resolve_labels(label_map, label)) {
	    //	  errorMsg = "Label " + label + " was used but not defined";
	    //	  goto parsing_done;
	    //	}
	    //	pscript.insert(ProtocolScript::value_type(current_script.protocol, current_script));
	    // }
	    // current_script = GlasnostScript();
	    // label_map.clear();

	    //} else if (word == "goto") {
	    if (word == "goto") {

	      expect = GOTO_ARGUMENT;

	    } else if (word == "start") {

	      expect = MEASURING;

	    } else if (word == "client" || word == "server") {

	      current_endpoint = (word == "client" ? CLIENT : SERVER);
	      expect = ENDPOINT_COMMAND;

	    } else if (word.length() > 1 && word[word.length()-1] == ':') {
	      // this is a label

	      string label = word.substr(0, word.length()-1);

	      if (!isAlphaNumeric(label)) {
		errorMsg = make_error(thisLine, "Labels can only contain alphanumeric characters", pos, totalNumLines);//, lineNumber);
		goto parsing_done;
	      }

	      if (!(label_map.insert(map<string, unsigned int>::value_type(label, current_script.commands.size()))).second) {
		errorMsg = make_error(thisLine, "Label \"" + label + "\" already defined", pos, totalNumLines);//, lineNumber);
		goto parsing_done;
	      }

	      expect = NOTHING;

	    } else {

	      errorMsg = make_error(thisLine, "Invalid command", pos, totalNumLines); //lineNumber);
	      goto parsing_done;
	    }

	  } else if (expect == ENDPOINT_COMMAND) {

	    if (word == "send") {

	      assert(current_send_command == 0);
	      current_send_command = new SendCommand(current_endpoint);
	      expect = SEND_PAYLOAD;

	    } else if (word.substr(0,6) == "pause(") {

	    	size_t comma = word.find_first_of(",");
	      if (comma == string::npos) {
		errorMsg = make_error(thisLine, "Pause command requires 2 comma separated integers", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }
	      size_t closed_par = word.find_first_of(")");
	      if (closed_par == string::npos) {
		errorMsg = make_error(thisLine, "Couldn't find closing parenthesis in pause command", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }

	      int sec, usec;
	      istringstream sec_iss(word.substr(6, comma-6));
	      istringstream usec_iss(word.substr(comma+1, closed_par - comma));
	      sec_iss >> sec;
	      if (sec_iss.fail() || sec < 0) {
		errorMsg = make_error(thisLine, "Invalid first parameter in pause command (must be a positive integer)", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }
	      usec_iss >> usec;
	      if (usec_iss.fail() || usec < 0) {
		errorMsg = make_error(thisLine, "Invalid second parameter in pause command (must be a positive integer)", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }

	      current_script.append_command(new PauseCommand(current_endpoint, sec, usec));

	      expect = NOTHING;

	      //cerr << "sec = " << sec << endl << " usec = " << usec << endl;

	    } else {
	      errorMsg = make_error(thisLine, "Invalid command", pos, totalNumLines); //, lineNumber);
	      goto parsing_done;
	    }

	  } else if (expect == SEND_PAYLOAD) {


	    if (word.substr(0,8) == "string(\"") {

	    	size_t quote = word.find_first_of("\"", 8);
	      string content;
	      if (quote != string::npos) {
		// the whole string statement is in one word
		if (quote == word.size()-1) {
		  errorMsg = make_error(line, "Payload string() statement without closed parenthesis", pos, totalNumLines); //, lineNumber);
		  goto parsing_done;
		}
		if (word.at(quote+1) != ')') {
		  errorMsg = make_error(line, "Payload string() statement without closed parenthesis", pos, totalNumLines); //, lineNumber);
		  goto parsing_done;
		}
		if (quote != word.length()-2) {
		  errorMsg = make_error(line, "Payload string() statement with trailing characters after closed parenthesis", pos, totalNumLines); //, lineNumber);
		  goto parsing_done;
		}


		content = word.substr(8,quote-8);

	      } else {

		content = word.substr(8);

		// the whole string statement comprises more words
		stringbuf buf;
		iss.get(buf, '\"');
		if (iss.get() != '\"') {
		  errorMsg = make_error(line, "Payload string() statement without right quote", pos, totalNumLines); //, lineNumber);
		  goto parsing_done;
		}
		if (iss.get() != ')') {
		  errorMsg = make_error(line, "Payload string() statement without closed parenthesis", pos, totalNumLines); //, lineNumber);
		  goto parsing_done;
		}

		content.append(buf.str());

	      }

	      assert(current_send_command != 0);
	      ((SendCommand*) current_send_command)->append_data_payload(content);


	      //stringbuf bug;


	    //size_t quote = word.find_first_of("\"");
	    //if (quote == string::npos)
	    // output_error(line, "Payload string() statement without closing right quote", pos, totalNumLines); //, lineNumber);



	    } else if (word.substr(0,5) == "byte(") {

	    	size_t par = word.find_first_of(')');
	      if (par == string::npos) {
		errorMsg = make_error(line, "Payload byte() statement without closed parenthesis", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }
	      if (par != word.length()-1) {
		errorMsg = make_error(line, "Payload byte() statement with trailing characters after closed parenthesis", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }


	      unsigned int cur = 5;
	      size_t comma;
	      do {

		comma = word.find_first_of(',', cur);
		string byte_str;

		if (comma != string::npos) {
		  byte_str = word.substr(cur, comma-cur);
		  cur = comma+1;
		} else {
		  byte_str = word.substr(cur, par-cur);
		}

		istringstream byte_iss(byte_str);
		unsigned int byte;
		byte_iss >> byte;
		if (byte_iss.fail() || byte > 255 || !isDigitString(byte_str)) {
		  errorMsg = make_error(line, "Payload byte() statement requires integer arguments between 0 and 255", pos, totalNumLines); //, lineNumber);
		  goto parsing_done;
		}

		assert(current_send_command != 0);
		((SendCommand*) current_send_command)->append_data_payload(string(1,char(byte)));

		//cerr << "byte = " << byte << endl;


	      } while (comma != string::npos);


	    } else if (word.substr(0,8) == "repbyte(") {

	    	size_t comma = word.find_first_of(',');
	    	size_t par = word.find_first_of(')');
	      if (comma == string::npos) {
		errorMsg = make_error(thisLine, "Payload repbyte() statement requires 2 comma seprated integers", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }
	      if (par == string::npos) {
		errorMsg = make_error(thisLine, "Payload repbyte() statement without closed parenthesis", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }
	      if (par != word.length()-1) {
		errorMsg = make_error(line, "Payload repbyte() statement with trailing characters after closed parenthesis", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }


	      string byte_str(word.substr(8, comma-8));
	      string rep_str(word.substr(comma+1, par-comma-1));
	      istringstream byte_iss(byte_str);
	      istringstream rep_iss(rep_str);

	      unsigned int byte;
	      byte_iss >> byte;
	      if (byte_iss.fail() || byte > 255 || !isDigitString(byte_str)) {
		errorMsg = make_error(line, "Payload repbyte() statement requires an integer between 0 and 255 as first argument", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }

	      unsigned int rep;
	      rep_iss >> rep;
	      if (rep_iss.fail() || !isDigitString(rep_str)) {
		errorMsg = make_error(line, "Payload repbyte() statement requires a positive integer as second argument", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }


	      assert(current_send_command != 0);
	      //((SendCommand*) current_send_command)->append_data_payload(string(rep,char(byte)));
	      ((SendCommand*) current_send_command)->append_repeat_payload(byte, rep);

	      ////cerr << "byterep = " << byte << " X " << rep << endl;



	    } else if (word.substr(0,8) == "prevmsg(") {

	    	size_t comma = word.find_first_of(',');
	    	size_t par = word.find_first_of(')');
	      if (par == string::npos) {
		errorMsg = make_error(thisLine, "Payload prevmsg() statement without closed parenthesis", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }
	      if (par != word.length()-1) {
		errorMsg = make_error(line, "Payload prevmsg() statement with trailing characters after closed parenthesis", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }

	      if (comma == string::npos) {
		errorMsg = make_error(thisLine, "Payload prevmsg() statement requires 2 comma sperated values", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }
	      string start_byte_str(word.substr(8,comma-8));
	      string num_bytes_str(word.substr(comma+1,par-comma-1));
	      istringstream start_byte_iss(start_byte_str);
	      istringstream num_bytes_iss(num_bytes_str);

	      unsigned int start_byte, num_bytes;
	      start_byte_iss >> start_byte;
	      num_bytes_iss >> num_bytes;
	      if (!isDigitString(start_byte_str) || start_byte_iss.fail()) {
		errorMsg = make_error(thisLine, "Payload prevmsg() statement requires a positive integer as first parameter", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }
	      if (!isDigitString(num_bytes_str) || num_bytes_iss.fail()) {
		errorMsg = make_error(thisLine, "Payload prevmsg() statement requires a positive integer as second parameter", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }


	      assert(current_send_command != 0);
	      ((SendCommand*) current_send_command)->append_prevmsg_payload(start_byte, num_bytes);


	    } else if (word.substr(0,8) == "randint(") {

	    	size_t comma = word.find_first_of(',');
	    	size_t par = word.find_first_of(')');
	      if (par == string::npos) {
		errorMsg = make_error(thisLine, "Payload randint() statement without closed parenthesis", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }
	      if (par != word.length()-1) {
		errorMsg = make_error(line, "Payload randint() statement with trailing characters after closed parenthesis", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }


	      if (comma == string::npos) {
		errorMsg = make_error(thisLine, "Payload radnint() statement requires 2 comma sperated values", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }

	      string low_str(word.substr(8,comma-8));
	      string high_str(word.substr(comma+1,par-comma-1));
	      istringstream low_iss(low_str);
	      istringstream high_iss(high_str);

	      unsigned int low, high;
	      low_iss >> low;
	      high_iss >> high;
	      if (!isDigitString(low_str) || low_iss.fail()) {
		errorMsg = make_error(thisLine, "Payload randint() statement requires a positive integer between 0 and " + intToStr(UINT_MAX) + " as first parameter", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }
	      if (!isDigitString(high_str) || high_iss.fail()) {
		errorMsg = make_error(thisLine, "Payload randint() statement requires a positive integer between 0 and " + intToStr(UINT_MAX) + " as second parameter", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }

	      if (low >= high) {
		errorMsg = make_error(thisLine, "Payload randint() requires two integer parameters, with the first one strictly lower than the second one", pos, totalNumLines); //, lineNumber);
		goto parsing_done;

	      }


	      assert(current_send_command != 0);
	      ((SendCommand*) current_send_command)->append_randint_payload(low, high);

	    } else if (word.substr(0,7) == "random(") {

	    	size_t par = word.find_first_of(')');
	      if (par == string::npos) {
		errorMsg = make_error(thisLine, "Payload random() statement without closed parenthesis", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }
	      if (par != word.length()-1) {
		errorMsg = make_error(line, "Payloadr random() statement with trailing characters after closed parenthesis", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }

	      string num_str(word.substr(7,par-7));
	      istringstream num_iss(num_str);

	      unsigned int num;
	      num_iss >> num;
	      if (!isDigitString(num_str) || num_iss.fail()) {
		errorMsg = make_error(thisLine, "Payload random() statement requires a positive integer as parameter", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }

	      assert(current_send_command != 0);
	      ((SendCommand*) current_send_command)->append_random_payload(num);


	    } else if (word.substr(0,4) == "int(") {


	    	size_t par = word.find_first_of(')');
	      if (par == string::npos) {
		errorMsg = make_error(line, "Payload int() statement without closed parenthesis", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }
	      if (par != word.length()-1) {
		errorMsg = make_error(line, "Payload int() statement with trailing characters after closed parenthesis", pos, totalNumLines); //, lineNumber);
		goto parsing_done;
	      }

	      unsigned int cur = 4;
	      size_t comma;
	      do {

		comma = word.find_first_of(',', cur);
		string int_str;

		if (comma != string::npos) {
		  int_str = word.substr(cur, comma-cur);
		  cur = comma+1;
		} else {
		  int_str = word.substr(cur, par-cur);
		}

		istringstream int_iss(int_str);
		unsigned int int_num;
		int_iss >> int_num;
		if (int_iss.fail() || !isDigitString(int_str)) {
		  errorMsg = make_error(line, "Payload int() statement requires positive integer arguments between 0 and " + intToStr(UINT_MAX), pos, totalNumLines); //, lineNumber);
		  goto parsing_done;
		}

		//cerr << "int = " << int_num << endl;

		assert(integer_length == 4);
		// we convert the integer to a 4-byte unsigned integer in network byte order
		uint32_t int_nb = htonl(int_num);
		string data;
		for (unsigned int i = 0; i < integer_length; ++i) {
		  data.append(1, ((char*) &int_nb)[i]);
		}
		assert(current_send_command != 0);
		((SendCommand*) current_send_command)->append_data_payload(data);


	      } while (comma != string::npos);


	    } else {

	      //cerr << word << endl;
	      errorMsg = make_error(thisLine, "Unknown payload statement", pos, totalNumLines); //, lineNumber);
	      goto parsing_done;

	    }

	  }

	}
      }
      if (expect != NOTHING && expect != SEND_PAYLOAD)  {
	errorMsg = make_error(thisLine, "Premature end of line", pos, totalNumLines);
	goto parsing_done;
      }
      if (expect == SEND_PAYLOAD) {
	assert(current_send_command != 0);
	if (current_send_command->length > (int) max_payload_size) {
	  errorMsg = make_error(thisLine, "Payload size of " + intToStr(current_send_command->length) + " bytes exceeds allowed maximum of " + intToStr(max_payload_size)  + " bytes", pos, totalNumLines);
	  goto parsing_done;
	}
	if (current_send_command->length == 0) {
	  errorMsg = make_error(thisLine, "Empty payload for send command", pos, totalNumLines);
	  goto parsing_done;
	}
	current_script.append_command(current_send_command);
	current_send_command = 0;
      }

    }

  }

  if (!current_script.protocol.empty()) {
    string label;
    if (!current_script.resolve_labels(label_map, label)) {
      errorMsg = "Label " + label + " was used but not defined";
      goto parsing_done;
    }
    if (current_script.commands.empty()) {
      errorMsg = "Protocol " + current_script.protocol + " does not contain any commands";
      goto parsing_done;
    }
    pscript.insert(ProtocolScript::value_type(current_script.protocol, current_script));
  }


  if (!pscript.empty())
    // script is valid!
    valid = true;
  else {
    errorMsg = "File does not contain any protocol description";
    goto parsing_done;
  }

 parsing_done:
  if (!valid)
    freeProtocolScript(pscript);
  return valid;
}



std::ostream& operator<<(std::ostream& os, GlasnostParser::GlasnostCommand& cm)
{
  unsigned int i;
  switch (cm.type) {

  case GlasnostParser::SEND:
    os << " SEND length: " << ((GlasnostParser::SendCommand*) &cm)->length << "\n";
    for (i = 0; i < ((GlasnostParser::SendCommand*) &cm)->payload.size(); ++i) {
      if (((GlasnostParser::SendCommand*) &cm)->payload[i].type == GlasnostParser::PayloadElement::DATA)
	os << "DATA: " << ((GlasnostParser::SendCommand*) &cm)->payload[i].data.size() << std::endl;
      else {
	if (((GlasnostParser::SendCommand*) &cm)->payload[i].type == GlasnostParser::PayloadElement::PREV_MSG)
	  os << "PREVMSG: ";
	else if (((GlasnostParser::SendCommand*) &cm)->payload[i].type == GlasnostParser::PayloadElement::RANDINT)
	  os << "RANDINT: ";
	else if (((GlasnostParser::SendCommand*) &cm)->payload[i].type == GlasnostParser::PayloadElement::RANDOM)
	  os << "RANDOM: ";
	else if (((GlasnostParser::SendCommand*) &cm)->payload[i].type == GlasnostParser::PayloadElement::REPEAT)
	  os << "REPEAT: ";
	else
	  os << "!!!!UNKNOWN PAYLOAD ELEMENT!!!!";

	os << ((GlasnostParser::SendCommand*) &cm)->payload[i].n << "-" << ((GlasnostParser::SendCommand*) &cm)->payload[i].k << std::endl;
      }
    }

    break;
  case GlasnostParser::GOTO:
    os << " GOTO " << ((GlasnostParser::GotoCommand*) &cm)->target_command + 1;
    break;
  case GlasnostParser::PAUSE:
    os << " PAUSE ";
    break;
  case GlasnostParser::START_MEASURING:
    os << " START_MEASURING ";
    break;
  }
  return os;
}




