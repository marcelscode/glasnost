#include "glasnost_parser.h"
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include "tools.h"

using namespace std;

void usage() {
	panic("Usage: script_validator <protocolScriptFile> {<maxPayloadSize> <maxErrorLineLen> <allowBundling?>}\n");
}


int main(int argc, char **argv){

  using namespace GlasnostParser;

	if (argc < 2) {
		usage();
	}

	bool allow_bundling = true;
	if (argc > 2) 
	  max_payload_size = atoi(argv[2]);
	if (argc > 3) 
	  max_err_line_len = atoi(argv[3]);
	if (argc > 4)
	  allow_bundling = atoi(argv[4]);

	ProtocolScript pscript;
	string errorMsg;
	bool correct = GlasnostParser::parseScript(argv[1], pscript, errorMsg, allow_bundling);	

	if(correct) {
	  string buf;		
	  string marshalled(string(argv[1]) + ".marshalled");
	  ofstream ofs(marshalled.c_str());
	  if (!ofs.is_open()) {
	    cout << "internal error: could not open file " << marshalled << endl;
	    exit(1);
	  }

	  buf.append(intToStr(pscript.size()));
	  buf.append(1, ':');	  

	  for (GlasnostParser::ProtocolScript::iterator i = pscript.begin();	       
	       i != pscript.end(); ++i) {
	    	    
	    i->second.serialize(buf);
	    
	    buf.append(1, ':');
	    
	    //cout << "protocol " << i->first << " port1=" << i->second.port1 << " port2=" << i->second.port2 << " with " << i->second.commands.size() << " commands\n";
	    //for (unsigned int n = 0; n < i->second.commands.size(); ++n)
	    // cout << n + 1 << ": " << *(i->second.commands[n]) << endl;	  
	    
	  }
	  
	  ofs << buf;
	  ofs.close();
	  cout << "Script " << argv[1] << " is valid\n";
	  //if (!allow_bundling) {
	  // const GlasnostScript& gs = pscript.begin()->second;
	  // cout << gs.protocol << endl << gs.port1 << endl << gs.port2 << endl << gs.duration << endl;	    
	  //}

	  
	  //DEBUG
	  //for (ProtocolScript::iterator i = pscript.begin(); i != pscript.end(); ++i)
	  // for (unsigned int n = 0 ; n < i->second.commands.size(); ++n)
	  //  cout << *(i->second.commands[n]) << endl;

	  freeProtocolScript(pscript);
	  
	} else{
	  cout << "Script " << argv[1] << " is NOT valid" << endl;
	  cout << errorMsg;
	  exit(1);
	}       

}

