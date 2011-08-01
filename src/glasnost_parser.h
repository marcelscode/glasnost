#ifndef GLASNOST_PARSER_H
#define GLASNOST_PARSER_H
#include <string>
#include <vector>
#include <map>
#include <iostream>

namespace GlasnostParser {

  enum EndPoint { SERVER, CLIENT };
  enum CommandType { SEND, GOTO, PAUSE, START_MEASURING };

  extern unsigned int max_err_line_len; // never ouput more than so many characters of a script line reporting an error
  extern unsigned int max_payload_size; // maximum size of a payload
  extern unsigned int integer_length; // bytes in a Glasnost script integer

  struct GlasnostCommand {
    
    inline GlasnostCommand(CommandType type_)
      : type(type_) {}

    inline virtual ~GlasnostCommand() {};

    virtual void serialize(std::string& buf) =0;
    
    CommandType type;    
  };

  struct GlasnostScript {
    
    inline GlasnostScript()
      : protocol(""), port1(0), port2(0), duration(0)
    {}

    void append_command(GlasnostCommand* new_command);
    void free_memory();
    bool resolve_labels(const std::map<std::string, unsigned int>& label_map, std::string& unresolved);
    void serialize(std::string& buf);

    
    std::string protocol;
    int port1,port2;
    int duration;

    std::vector<GlasnostCommand*> commands;
  };

  typedef std::map<std::string, GlasnostScript> ProtocolScript;

  void freeProtocolScript(ProtocolScript& pscript);

  
  struct PayloadElement {

    PayloadElement()
      : type(DATA), n(0), k(0)
    {}

    void serialize(std::string& buf);
    
    enum { PREV_MSG, DATA, RANDOM, RANDINT, REPEAT } type;
    unsigned int n, k; 
    // Used for RANDINT and PREVMSG
    // RANDINT => random integer between n and k
    // PREV_MSG => content of previous message starting at n, k bytes long    
    // RANDOM => n random bytes
    // REPEAT => byte n repeated k times

    std::string data;
  };
  
  struct SendCommand : public GlasnostCommand {

    inline SendCommand(EndPoint endpoint_)
      : GlasnostCommand(SEND), endpoint(endpoint_), length(0)
    {}

    EndPoint endpoint;
    std::vector<PayloadElement> payload;
    int length;

    void serialize(std::string& buf);

    void append_data_payload(const std::string& str);
    void append_randint_payload(int low, int high);
    void append_random_payload(int length);
    void append_prevmsg_payload(int offset, int length);
    void append_repeat_payload(unsigned int byte, int repeat);
    

  };

  struct StartMeasuringCommand : public GlasnostCommand {

    inline StartMeasuringCommand()
      : GlasnostCommand(START_MEASURING)
    {}

    void serialize(std::string& buf);
  };


  struct GotoCommand : public GlasnostCommand {
    
    inline GotoCommand(const std::string& label_)
      : GlasnostCommand(GOTO), label(label_), target_command(-1) 
    {}

    void serialize(std::string& buf);

    std::string label;
    unsigned int target_command;
  };

  struct PauseCommand : public GlasnostCommand {
    
    inline PauseCommand(EndPoint endpoint_, int sec_, int usec_)
      : GlasnostCommand(PAUSE), endpoint(endpoint_), sec(sec_), usec(usec_)
    {}

    void serialize(std::string& buf);

    EndPoint endpoint;
    int sec;
    int usec;
  };

     
  bool parseScript(const std::string& scriptFile, ProtocolScript& pscript, std::string& errorMsg, bool allow_bundling = true);
  bool parseScript(std::ifstream& ifs, ProtocolScript& pscript, std::string& errorMsg, bool allow_bundling = true);  

  bool isValidProtocolName(const std::string& str);
  
  std::string make_error(const std::string& line, const std::string& message, int errpos, int linenum);
  void compress_spaces(std::string& str);
  

};


std::ostream& operator<<(std::ostream& os, GlasnostParser::GlasnostCommand& cm);



#endif
