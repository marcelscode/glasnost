package glasnost
{
  import flash.net.URLRequest;
  import flash.net.navigateToURL;
  
  import mx.controls.ProgressBar;
  
  public class GlasnostReplayer {
    
    public static const VERSION:String = "28.02.2013";

    public static var sysinfo:String = "";
    public var nextPage:String = "bb/failed";
    public var expParam:String;
    
    public var rpw:ReplayWorker = null;
    public var mServer:String;
    public var mScriptFile:String = null;
    public var mProtocol:Vector.<String> = new Vector.<String>();
    public var mPort:Array = new Array();
    public var testid:String = "unknown";
    public var up:Boolean = false
    public var down:Boolean = false;
    public var repeat:int = 2;
    public var duration:int = 20;
    public var progress_bar:ProgressBar = null;
    
    public var finished:Boolean = false;
    
    private var browserWorkaround:Boolean = false;
    // progress, use setDone(), setTotalLength()
    private var done:Number = 0;
    private var totalLength:Number = 100;

    
    public function GlasnostReplayer(paramList:Object, progress_bar:ProgressBar) { // init() in Applet version
      this.progress_bar = progress_bar;
      down = Boolean(paramList["down"]);
      up = Boolean(paramList["up"]);
      repeat = parseInt(paramList["repeat"]);
      duration = parseInt(paramList["duration"]);
      mProtocol[0] = paramList["protocol1"];
      if (paramList.hasOwnProperty("protocol2")) {
        mProtocol[1] = paramList["protocol2"];
      }  else {
        trace("No second protocol specified, will send control flow instead.");
      }
      if (mProtocol[0] == null) {
        trace("Misconfiguration: You have to specify the protocols to use!");
        return;
      }
      
      if (!up && !down) {
        trace("Misconfiguration: Choose either or both up and down traffic!");
        return;
      }
      
      nextPage = paramList["nextPage"];
      mServer = paramList["server"];
      
      trace(mServer);
      trace("Starting Glasnost Replayer version " + VERSION);
      
      var port:String = paramList["port"];
      if ((port != null)
        && ((parseInt(port) >= 0) || (parseInt(port) == -1)))
        mPort[0] = parseInt(port);
      else
        mPort[0] = 0;
      var port2:String = paramList["port2"];
      if ((port2 != null)
        && ((parseInt(port2) >= 0) || (parseInt(port2) == -2)))
        mPort[1] = parseInt(port2);
      else
        mPort[1] = -3;
      
      testid = paramList["ID"];
      
      if (mProtocol.length == 2)
        expParam = "protocol1=" + mProtocol[0] + "&protocol2=" + mProtocol[1]
          + "&down=" + this.down + "&up=" + this.up + "&repeat=" + this.repeat
          + "&duration=" + this.duration + "&";
      else
        expParam = "protocol1=" + mProtocol[0] + "&down=" + this.down + "&up="
          + this.up + "&repeat=" + this.repeat + "&duration=" + this.duration
          + "&";

      if (paramList.hasOwnProperty("browserWorkaround")) {
        browserWorkaround = Boolean(paramList["browserWorkaround"]);
      }
      
      // DELME
      printItem("Monkey");
      setDone(50);
      
      rpw = new ReplayWorker(this);
      rpw.readInScript("protocols.spec.marshalled", new Vector.<String>("Bitttorrent"));
      rpw.initialSetup(up, down, repeat, duration);
      rpw.run();
    }
    
    public function printItem(newWord:String):void {
      progress_bar.label = newWord;
    }
    
    public function setDone(done:Number) {
      this.done = done;
      progress_bar.setProgress(this.done, this.totalLength);
    }
    
    public function setTotalLength(totalLength:Number) {
      this.totalLength = totalLength;
      progress_bar.setProgress(this.done, this.totalLength);      
    }
    
    public function displayResultPage(url:String): void {
      navigateToURL(new URLRequest(url), "_self"); 
    }
  }
}
import flash.events.ProgressEvent;
import flash.events.TimerEvent;
import flash.net.Socket;
import flash.utils.ByteArray;
import flash.utils.Dictionary;
import flash.utils.Endian;
import flash.utils.Timer;

import mx.core.ByteArrayAsset;

import glasnost.GlasnostReplayer;

import resource.Resource;

class GlasnostScript {
  var protocol:String = null;
  var port:Vector.<int> = new Vector.<int>();
  var duration:int = 0; // in milliseconds!

  var commands:Vector.<GlasnostCommand> = new Vector.<GlasnostCommand>();
  
  public function GlasnostScript(stream:ByteArray) {
    var buf:ByteArray = null;
    var label:String = null;
    var p:int = 0;
    
    buf = GlasnostCommand.readToColon(stream);
    label = buf.toString();
    if (label != "PROTO")
      throw new Error("could not create GlasnostScript, expected PROTO, found " + label);
    buf = GlasnostCommand.readToColon(stream);
    this.protocol = buf.toString();    
    
    
    buf = GlasnostCommand.readToColon(stream);
    label = buf.toString();
    if (label != "PORT1")
      throw new Error("could not create GlasnostScript, expected PORT1, found " + label);
    buf = GlasnostCommand.readToColon(stream);
    p = parseInt(buf.toString()); 
    if (p > 0)
      port.push(p);
    
    buf = GlasnostCommand.readToColon(stream);
    label = buf.toString();
    if (label != "PORT2")
      throw new Error("could not create GlasnostScript, expected PORT2, found " + label);
    buf = GlasnostCommand.readToColon(stream);
    p = parseInt(buf.toString()); 
    if (p > 0)
      port.push(p);
    
    buf = GlasnostCommand.readToColon(stream);
    label = buf.toString();
    if (label != "DURATION")
      throw new Error(
        "could not create GlasnostScript, expected DURATION, found "
        + label);
    buf = GlasnostCommand.readToColon(stream);
    this.duration = parseInt(buf.toString()) * 1000;
    
    buf = GlasnostCommand.readToColon(stream);
    var com:int = parseInt(buf.toString());
    
    for (var i:int = 0; i < com; ++i) {
      
      var new_com:GlasnostCommand = null;
      buf = GlasnostCommand.readToColon(stream);
      var type:String = buf.toString();
      if (type == "SEND")
        new_com = new SendCommand(stream);
      else if (type == "PAUSE")
        new_com = new PauseCommand(stream);
      else if (type == "START_MEASURING")
        new_com = new StartMeasuringCommand();
      else if (type == "GOTO")
        new_com = new GotoCommand(stream);
      
      this.commands.push(new_com);
    }    
  }
}

import flash.utils.getTimer;
import flash.utils.setTimeout;
import flash.crypto.generateRandomBytes;

class ReplayWorker {
  const ConnectTimeout:Number = 20000;
  const DefaultDuration:Number = 10000;
  const MaximumDuration:Number = 30000;
  const Pause:Number = 500; // in milliseconds - time between two experiments

  
  var gr:GlasnostReplayer = null;
  
  const commandPort:int = 19970;
  
  var myIP:String = null;
  var myHostname:String = null;
  var serverIp:String = null;

  var serverPort:Vector.<int> = Vector.<int>([0,0]);
  var protocol:Vector.<String>;
  
  var scriptFile:String = "protocols.spec.marshalled";
  
  var specInJar:Boolean = true;
  var protocolScript:Dictionary = new Dictionary(); // String => GlasnostScript
  
  var duration:Number = -1; // in milliseconds
  var totalDuration:int = 0; // in seconds
  
  var isTerminated:Boolean = false;
  var reset:Boolean = false;
  var start:int;
  var end:int;
  var lastState:int;
  var bytesTransmitted:Number = 0;
  var bytesReceived:Number = 0;

  // Control variables
  var numberOfRepeats:int = 1;
  var upstream:Vector.<int> = Vector.<int>([0,0]);
  var downstream:Vector.<int> = Vector.<int>([0,0]);
  
  var results:String = ""
  var backLog:String = "";
  
  var exp:int = 0; 
  

  
  
  public function ReplayWorker(gr:GlasnostReplayer) {
    this.gr = gr;
    this.protocol = gr.mProtocol;
    this.serverIp = gr.mServer;
    trace("new ReplayWorker(): "+this.serverIp);
  }
  
  var bound:int = 0;
  function addToBound(newBound:int) {
    this.bound += newBound;
    gr.printItem(""+bound);
    gr.setDone(bound);
  }
  
  function readInScript(scriptFile:String, proto:Vector.<String>):Vector.<String> {
    var script:ByteArrayAsset
    try {
      if (specInJar) {
        script = Resource.getBuiltInProtocols();
        
      }
    } catch (e:Error) {
      
      
    }
        
      
    trace("reading protos ");
    try {
      // read number of protocols in the file
      var buf:ByteArray = GlasnostCommand.readToColon(script);
      var num_of_protos:int = parseInt(buf.toString()); 
      
      for (var p:int = 0; p < num_of_protos; p++) {
        var gs:GlasnostScript = new GlasnostScript(script);
        protocolScript[gs.protocol] = gs;
        
        trace("found proto " + gs.protocol + " with " + gs.commands.length + " " + protocolScript[gs.protocol] +" instructions, ports=");
        for each (var pn:int in gs.port) {
          trace("  "+pn + " ");
        }
        trace("duration=" + gs.duration);
      }
    } catch (e:Error) {
      var id:String = null;
      if (gr != null)
        id = gr.testid;
      trace("While parsing script(s): " + e);
      handleFatalError("Error while parsing the bytecode for " + scriptFile,
        "id=" + id + "&mid=21&msg=bytecode%20for%20scriptFile%20invalid",
        6, e);
    } 
    
    var unknownProtocol:Vector.<String> = new Vector.<String>();
    for each (var pName:String in proto) {
      if (!protocolScript.hasOwnProperty(pName)) {
        unknownProtocol.push(pName);
      }
    }
    return unknownProtocol;
  }  
  
  /**
   * Given command line parameters, calculate how long the whole measurement
   * run will take and set up the internal variables to control the
   * measurement
   */
  function initialSetup(up:Boolean, down:Boolean, repeat:int, duration:int):void {
    
    if (repeat > 0)
      this.numberOfRepeats = repeat;
    if (duration > 0) {
      this.duration = duration * 1000;
    }
    
    if (up) {
      upstream[0] += repeat;
      if ((protocol.length == 1)
        || ((protocol.length > 1) && protocol[1] != "none")) {
        upstream[1] += repeat;
        totalDuration += 10; // For socket warm-up
      }
    }
    if (down) {
      downstream[0] += repeat;
      if ((protocol.length == 1)
        || ((protocol.length > 1) && protocol[1] != "none")) {
        downstream[1] += repeat;
        totalDuration += 10; // For socket warm-up
      }
    }
    
    if (serverPort[1] > -3) {
      upstream[0] *= 2;
      upstream[1] *= 2;
      downstream[0] *= 2;
      downstream[1] *= 2;
    }
    
    var d:Number = this.duration;
    if (d <= 0)
      d = DefaultDuration; // Will be set later, so use this default value
    // here
    
    totalDuration += (int) ((Pause + d) / 1000)
      * (upstream[0] + upstream[1] + downstream[0] + downstream[1]);
    
//    if (gr != null) {
//      cd = new Countdown(gr, totalDuration);
//      gr.totalLength = totalDuration;
//      cd.start();
//    }
  }
  
  /**
   * generateRandomBytes() can only generate 1024 bytes, because Adobe sucks.  This calls is a billion times.
   */
  function generateRandomBytesA(num:int):ByteArray {
    var ret:ByteArray = new ByteArray();
    while (ret.length < num) {
      var moreLen:int = Math.min(num-ret.length, 1024);
      generateRandomBytes(moreLen).readBytes(ret, ret.length, moreLen);
    }
    
    return ret;
  }
  
  function createMessage(payload:Vector.<PayloadElement>, prevmsg:ByteArray):ByteArray {
    var buf:ByteArray = new ByteArray();
    buf.endian = Endian.BIG_ENDIAN;
    
    for each (var p:PayloadElement in payload) {
      if (prevmsg == null) {
        trace("createMessage("+p+",null)");
      } else {
        trace("createMessage("+p+",<"+prevmsg.position+","+prevmsg.length+">)");        
      }
      if (p.type == PayloadType.DATA) {
        buf.writeBytes(p.data, 0, p.data.length);
      } else if (p.type == PayloadType.PREV_MSG) {
        var offset:int = p.n;
        var len:int = p.k;
        if (offset + len > prevmsg.length) {
          trace("Size of prevous message exceeded, truncating message (size="
            + prevmsg.length + ", offset="
            + offset + ", len="
            + len);
          len = prevmsg.length - offset;
        }
        
        buf.writeBytes(prevmsg, offset, len);
        
      } else if (p.type == PayloadType.RANDOM) {
        var len:int = p.n;
        var randBytes:ByteArray = generateRandomBytesA(len);
        buf.writeBytes(randBytes,0,len);
      } else if (p.type == PayloadType.REPEAT) {
        var len:int = p.k;
        for (var i:int = 0; i < len; ++i) {
          buf.writeByte(p.n);
        }
      } else if (p.type == PayloadType.RANDINT) {
        
        var xmin:int = p.n;
        var xmax:int = p.k;
        // this alyways takes 4 bytes in Java
        buf.writeInt((int)(xmin + (Math.random() * (xmax - xmin + 1))));
      }
      
    }
    buf.position = 0;
    return buf;
  }
  
  function list(dict:Dictionary): void {
    for (var obj:Object in dict) {
      trace(obj);
    }
  }
  
  function isEmpty(dict:Dictionary):Boolean {
    for each(var obj:Object in dict) {
      if(obj != null) {
        return false
      }
    }
    return true;
  }
  
  var runTransferContinuation:Function = null; // called in doneTransfer(), will get one argument:transferSuccessful 
  var sChannel:Socket = null;
  var isServer:Boolean = false;
  function runTransfer(sChannel:Socket, proto:String, timeout:int, isServer:Boolean, sendControlFlow:Boolean, runTransferContinuation:Function):void {
    trace("runTransfer");
    this.runTransferContinuation = runTransferContinuation;
    this.sChannel = sChannel;
    this.isServer = isServer;
    
    if (sChannel == null) {
      start = getTimer();
      end = start;
      trace("Socket not connected. Cannot run experiment.");
      runTransferContinuation(false);
    }
    
    if (isEmpty(protocolScript)) { // Should not happen
      trace("could not find any script, attempting to read");
      var proto_t:Vector.<String> = new Vector.<String>();
      if (readInScript(scriptFile, proto_t).length > 0)
        runTransferContinuation(false);
    }
    
    // No protocols found in script file!
    // (readInScript() already outputs error)
    if (isEmpty(protocolScript) || !protocolScript.hasOwnProperty(proto)) {
      runTransferContinuation(false);
    }
    
    thisScript = protocolScript[proto];
    
    now = getTimer();
    start = now;
    
    endTime = now + timeout; // expected end of transfer
    lastPacket = now;
    pause = 0;
    
    
    bytesTransmitted = 0;
    bytesReceived = 0;
    lastState = -1;
    startMeasuring = false;
    protocolError = false;
    
    linebuf = null;
    found = false;
    lineno = 1;
    
    next_command_index = 0;
    
    runTransferHelper();
  }
  
  var thisScript:GlasnostScript;
  var now:int = 0;
  var endTime:int = 0; // expected end of transfer
  var lastPacket:int = 0;
  var pause:int = 0;
  
  
  var startMeasuring:Boolean = false;
  var protocolError:Boolean = false;
  
  var linebuf:String = null;
  var found:Boolean = false;
  var lineno:int = 1;
  
  var next_command_index:int = 0;
  var weSend:Boolean = false;

//  var commandChannel:Socket = null;
//  var serverCommands:Vector.<String> = new Vector.<String>();
//  var nextCommandCallback:Function = null;
//  var readingCommand:ByteArray = new ByteArray();
//  public static const NEWLINE:int = int("\n".charCodeAt(0));
  

  
  var waitingForLen:int = -1;
  var serverData:Vector.<ByteArray> = null; // this fills up until it's longer than waitingForLen

  /**
   * read everything onto a ByteArray and put it on serverData 
   */
  function incomingTransportData( event:ProgressEvent ):void {
    trace("incomingTransportData:"+sChannel.bytesAvailable);
    var bytes:ByteArray = new ByteArray();
    sChannel.readBytes(bytes, 0, sChannel.bytesAvailable);
    serverData.push(bytes);
    handleRead();
  }
  
  function waitForRead(len:int):void {
    trace("waitForRead("+len+")");
    if (waitingForLen > -1) {
      throw new Error("waitForRead() already waiting for read");
    }
    waitingForLen = len;
    handleRead();
  }

  /**
   * converts serverData to receivingMessage  
   */
  function handleRead():void {
    if (waitingForLen < 0) {
      trace("waitForRead(): not waiting for any bytes");
      return;
    }
    
    var len:int = 0;
    for each(var buf:ByteArray in serverData) {
      len+=buf.bytesAvailable;
    }
    
    if (len < waitingForLen) {
      trace("waitForRead(): waiting for more bytes:"+len+" of "+waitingForLen);
      return;
    }
    
    last_received_message = new ByteArray();
    while (last_received_message.length < waitingForLen) {
      serverData[0].readBytes(last_received_message, last_received_message.length, Math.min(serverData[0].bytesAvailable, waitingForLen-last_received_message.length));
      if (serverData[0].bytesAvailable < 1) {
        serverData.shift(); // get rid of it
      }
    }
    var temp:int = waitingForLen;
    waitingForLen = -1;
    doneRead(temp);
  }
  
  function doneRead(len:int) {
    trace("doneRead("+len+")");
    lastPacket = getTimer();
    bytesReceived += len;
    
    lastState = next_command_index;
    next_command_index++;    
    
    runTransferHelper();
  }
  
  
  
  function sendOrReceivePayload():void {
    if (message_payload == null) {
      trace("sendOrReceivePayload("+weSend+")");
    } else {
      trace("sendOrReceivePayload("+weSend+","+message_payload.position+ " / "+message_payload.length+")");
    }
    pause = 0;
    if (startMeasuring) {
      start = getTimer();
      bytesTransmitted = 0;
      bytesReceived = 0;
      startMeasuring = false;
    }
    
    if (weSend) {
      trace("writePacket("+message_payload.position+ " / "+message_payload.length+" avail:"+message_payload.bytesAvailable+")");

      // trace("Sending " + toSend + " bytes");
      
      // DEBUG
      // try {
      // byte[] tempb = new byte[toSend];
      // message_payload.get(tempb);
      // message_payload.rewind();
      // trace("SENDING:\n" + (new String(tempb, "US-ASCII")));
      // for (int i =0; i < tempb.length; ++i)
      // System.out.print(tempb[i] + " ");
      // System.out.println();
      // } catch (Exception e) {
      // }
      
      sChannel.writeBytes(message_payload, message_payload.position, message_payload.length);
      sChannel.flush();
      trace("sendOrReceivePayload() wrote:"+message_payload.length+" bytes");
      
      lastPacket = getTimer();
      bytesTransmitted += message_payload.length;
      
      last_received_message = message_payload;  // always holds the previous packet
      message_payload = null;
      
      lastState = next_command_index;
      
      next_command_index++;
      runTransferHelper();
    } else {
      
      waitForRead(send_com.length);
      return;
    }
    
  }
  
  var message_payload:ByteArray = null;
  var last_received_message:ByteArray = null;
  var send_com:SendCommand;
  /**
   * this is the inside the while loop in runTransfer() 
   */
  function runTransferHelper(): void {
    now = getTimer();
    if (now >= endTime) {
      trace("Time is up, ending");
      doneTransfer();
    }
    
    if (next_command_index < thisScript.commands.length) {
      
      var curr_com:GlasnostCommand = thisScript.commands[next_command_index];
      trace("executing command " + next_command_index + " of " + thisScript.commands.length + " " + curr_com);

      // trace("executing command " +
      // Integer.toString(next_command_index) + " of " +
      // thisScript.commands.size());
      
      if (curr_com.type == CommandType.SEND) {
        
        weSend = false;
        send_com = curr_com as SendCommand;
        if (send_com.endpoint == EndPoint.CLIENT) {
          weSend = !isServer;
        } else {
          weSend = isServer;
        }
        
        if (weSend && sendControlFlow) {
          trace("send a:"+weSend);
          message_payload = generateRandomBytesA(send_com.length);
        } else if (weSend) {
          trace("send b:"+weSend);
          // Question: why do we create a message even when we do not have to
          // send? (i.e. weSend=false)
          message_payload = createMessage(send_com.payload, last_received_message);
        }
        
        now = getTimer();
        if (now >= endTime) {
          trace("Time is up, ending");
          doneTransfer();
        }
        
        // Honor spacing between packets while sending
        if (pause > 0) {
          
          // Or add spacing to timing of last sent packet?
          pause -= (now - lastPacket);
        }
        if (pause > 0) {
          setTimeout(sendOrReceivePayload, pause);
          return;
        } else {
          sendOrReceivePayload();
          return;
        }      
      } else if (curr_com.type == CommandType.PAUSE) {
        
        var pause_com:PauseCommand = curr_com as PauseCommand;
        
        weSend = false;
        if (pause_com.endpoint == EndPoint.SERVER)
          weSend = isServer;
        else
          weSend = !isServer;
        
        if (weSend) {
          
          pause = (((int) (pause_com.sec)) * 1000)
            + (((int) (pause_com.usec)) / 1000);
          // trace("Pausing for " + pause + " milliseconds");
        }
        
        next_command_index++;
        
      } else if (curr_com.type == CommandType.START_MEASURING) {
        
        // trace("Start measuring");
        startMeasuring = true;
        next_command_index++;
        
      } else if (curr_com.type == CommandType.GOTO) {
        
        var goto_com:GotoCommand = curr_com as GotoCommand;
        // trace("Goto command: jumping to command " +
        // goto_com.target_command);
        next_command_index = goto_com.target_command;
      }
      runTransferHelper();      
    } else {    
      doneTransfer();
    }
  }
  
  function doneTransfer():void {
    lastState = next_command_index;
    end = getTimer();
    
    trace("End of transfer; " + bytesTransmitted
      + " bytes transferred and " + bytesReceived + " bytes received");
    
    runTransferContinuation(!protocolError && ((bytesTransmitted + bytesReceived) > 0));
    
  }
  
  

  /** ***************************** read commands from server ****************************
   * This section reads commands from the server and stores them in serverCommands.  readNextCommand() 
   * either returns the next command, or saves the callback until a new command arrives
   */
  var commandChannel:Socket = null;
  var serverCommands:Vector.<String> = new Vector.<String>();
  var nextCommandCallback:Function = null;
  var readingCommand:ByteArray = new ByteArray();
  public static const NEWLINE:int = int("\n".charCodeAt(0));

  /**
   * scan until NEWLINE, then add it to serverCommands 
   */
  private function incomingCommandData( event:ProgressEvent ):void {
    trace("incomingCommandData:"+commandChannel.bytesAvailable);
    while (commandChannel.bytesAvailable > 0) {
      var foo:int = commandChannel.readByte();
      if (foo == NEWLINE) {
        serverCommands.push(readingCommand.toString());
        readingCommand.clear();
      } else {
        readingCommand.writeByte(foo);
      }
    }
    
    if (serverCommands.length > 0 && nextCommandCallback != null) {
      var currCallback:Function = nextCommandCallback;
      nextCommandCallback = null;
      var ret:String = serverCommands.shift();
      trace("readNextCommand():" + ret);
      currCallback(ret);
    }
    trace("done incomingCommandData");
  }
  
  /**
   * Read until newline
   * 
   * callback takes a string
   */
  function readNextCommand(callback:Function):void {
    if (nextCommandCallback != null) {
      throw new Error("readNextCommand() already had a callback");
    }
    if (serverCommands.length > 0) {
      nextCommandCallback(serverCommands.shift());
    } else {
      trace("setting nextCommandCallback");
      nextCommandCallback = callback;
    }
  }
  
  /*********************************** END read commands from server ****************************/
  
  function startsWith(str:String, substr:String):Boolean {
    if (substr.length > str.length) return false;
    return str.substr(0,substr.length) == substr;
  }

  function endsWith(str:String, substr:String):Boolean {
    if (substr.length > str.length) return false;
    return str.substr(str.length-substr.length,substr.length) == substr;  // off by 1?
  }
  
  function setupSocket(serverIp:String, port:int): Socket {
    trace("setupSocket("+serverIp+","+port+")");
    var socket:Socket = new Socket(serverIp, port);
    waitingForLen = -1; 
    serverData = new Vector.<ByteArray>();
    socket.addEventListener(ProgressEvent.SOCKET_DATA, incomingTransportData, false, 500);
    
    return socket;
  }
    
  /**
   * Similar to ReplayWorker.run() in Applet
   */
  function run() {
    trace("Connecting to commandChannel:"+serverIp+":"+commandPort);
    commandChannel = new Socket(serverIp, commandPort);
    commandChannel.addEventListener(ProgressEvent.SOCKET_DATA, incomingCommandData, false, 500);
    
    var timer:Timer = new Timer(1000);
    timer.addEventListener(TimerEvent.TIMER, function(evt:TimerEvent):void {
      trace("timer:"+commandChannel.bytesPending+" "+commandChannel.bytesAvailable);
    });
    timer.start();
    trace("Connected to commandChannel.");
    
    initialCommunicationAndSetup(commandChannel);
    
    // continued in runNextFlow()
  }
  
  /**
   * in applet, this is the while block in run() after initialCommunicationAndSetup()
   */
  var sendControlFlow:Boolean = false;
  function runNextFlow():void {
    trace("run2");  

    var commandStr:String = null;
    
    
    if (!isTerminated
      && ((upstream[0] + upstream[1] + downstream[0] + downstream[1]) > 0)) {
      
      // Command string:
      // "replay <Protocol> <server/client> <duration> port <port> .\n"
      var proto:String = null;
      var gscript:GlasnostScript = null;
      var isServer:Boolean = false;
      sendControlFlow = false;
      var timeout:Number;
      
      // This will first execute all upstream experiments and then downstream
      // experiments
      if ((upstream[0] > 0) && (upstream[0] >= upstream[1])) {
        proto = protocol[0];
        gscript = protocolScript[proto];
        isServer = true;
        
        timeout = duration;
        if ((timeout <= 0) && gscript.duration > 0) { // duration = 0 equals
          // to unsepecified
          timeout = gscript.duration;
          trace("Setting test duration to " + timeout
            + " as set by the test script.");
        }
        
        if (timeout <= 0)
          timeout = DefaultDuration;
        
      } else if (upstream[1] > 0) {
        if (protocol.length > 1)
          proto = protocol[1];
        else {
          proto = protocol[0];
          sendControlFlow = true;
        }
        gscript = protocolScript[proto];
        isServer = true;
        timeout = duration;
        if ((timeout <= 0) && gscript.duration > 0) {
          timeout = gscript.duration;
          trace("Setting test duration to " + timeout
            + " as set by the test script.");
        }
        
        if (timeout <= 0)
          timeout = DefaultDuration;
      } else if ((downstream[0] > 0) && (downstream[0] >= downstream[1])) {
        proto = protocol[0];
        gscript = protocolScript[proto];
        isServer = false;
        
        timeout = duration;
        if ((timeout <= 0) && gscript.duration > 0) {
          timeout = gscript.duration;
          trace("Setting test duration to " + timeout
            + " as set by the test script.");
        }
        
        if (timeout <= 0)
          timeout = DefaultDuration;
        timeout += 1000;
      } else if (downstream[1] > 0) {
        if (protocol.length > 1)
          proto = protocol[1];
        else {
          proto = protocol[0];
          sendControlFlow = true;
        }
        isServer = false;
        gscript = protocolScript[proto];
        
        timeout = duration;
        if ((timeout <= 0) && gscript.duration > 0) {
          timeout = gscript.duration;
          trace("Setting test duration to " + timeout
            + " as set by the test script.");
        }
        
        if (timeout <= 0)
          timeout = DefaultDuration;
        timeout += 1000;
      } else {
        shutdown();
      }
      assert (proto != null);
      
      if (timeout > MaximumDuration) {
        timeout = MaximumDuration;
        trace("Restricting test duration to " + timeout
          + " which is the maximum configured in Glasnost.");
      }
      
      var port:int;
      if ((serverPort[1] > -3) && (upstream[0] <= 0) && (upstream[1] <= 0)
        && (downstream[0] <= numberOfRepeats)
        && (downstream[1] <= numberOfRepeats)) {
        port = serverPort[1];
        // if((port <= 0) && protocolPort.containsKey(proto) &&
        // (protocolPort.get(proto).length > 1)){
        if ((port <= 0) && gscript.port.length > 1) {
          port = gscript.port[1];
          trace("Setting port to " + port
            + " as set by the test script.");
          serverPort[1] = port;
          // if(gr != null)
          // gr.mPort[1] = serverPort[1];
        }
        
      } else if ((serverPort[1] > -3) && (upstream[0] <= numberOfRepeats)
        && (upstream[1] <= numberOfRepeats)
        && ((upstream[0] > 0) || (upstream[1] > 0))) {
        port = serverPort[1];
        if ((port <= 0) && gscript.port.length > 1) {
          port = gscript.port[1];
          trace("Setting port to " + port
            + " as set by the test script.");
          serverPort[1] = port;
          // if(gr != null)
          // gr.mPort[1] = serverPort[1];
        }
      } else {
        port = serverPort[0];
        if ((port <= 0) && gscript.port.length > 0) {
          port = gscript.port[0];
          trace("Setting port to " + port
            + " as set by the test script.");
          serverPort[0] = port;
          // if(gr != null)
          // gr.mPort[0] = serverPort[0];
        }
      }
      
      // Transmit over command socket what to do next and wait for answer
      
      commandStr = null; // Command string:
      // "replay <Protocol> <server/client> <duration> port <port> .\n"
      if ((upstream[0] > 0) && (upstream[0] >= upstream[1])) {
        commandStr = "replay " + proto + " client "
          + (int) (1 + (timeout / 1000)) + " port " + port + " .\n";
        upstream[0]--;
      } else if (upstream[1] > 0) {
        commandStr = "replay "
          + ((protocol.length > 1) ? protocol[1] : protocol[0])
          + " client " + (int) (1 + (timeout / 1000)) + " port " + port
          + ((protocol.length == 1) ? " controlFlow" : "") + " .\n";
        upstream[1]--;
      } else if ((downstream[0] > 0) && (downstream[0] >= downstream[1])) {
        commandStr = "replay " + protocol[0] + " server "
          + (int) ((timeout / 1000) - 1) + " port " + port + " .\n";
        downstream[0]--;
      } else if (downstream[1] > 0) {
        commandStr = "replay "
          + ((protocol.length > 1) ? protocol[1] : protocol[0])
          + " server " + (int) ((timeout / 1000) - 1) + " port " + port
          + ((protocol.length == 1) ? " controlFlow" : "") + " .\n";
        downstream[1]--;
      }
      
      if (commandStr == null) {
        // trace("FATAL: Do not know what experiment to run next. Aborting.");
        var id:String = null;
        if (gr != null) {
          id = gr.testid;
        }
        handleFatalError("Setup failed", "id=" + id + "&msg=No%20command", 30);
        return;
      }
      trace("Sending command: " + commandStr);
      commandChannel.writeUTFBytes(commandStr);
      commandChannel.flush();
      
      readNextCommand(function(nextCommand:String):void {
        trace(nextCommand);
        
        if (nextCommand == null) {
          trace("No response from server.");
          return;
        } else if (startsWith(nextCommand,"ok")) {
          trace("Server responded with OK.");
        } else if (startsWith(nextCommand,"port ")) {
          var parts = nextCommand.split(" ");
          
          // Change standard port to the one we got from the server
          if (commandStr.indexOf("port " + serverPort[0].toString()) != -1) {
            serverPort[0] = parseInt(parts[1]);
            // if(gr != null)
            // gr.mPort[0] = serverPort[0];
          } else if ((serverPort[1] > -3)
            && commandStr.indexOf("port " + serverPort[1].toString()) != -1) {
            serverPort[1] = parseInt(parts[1]);
            // if(gr != null)
            // gr.mPort[1] = serverPort[1];
          }
          
          trace("Server changed port to " + parts[1] + ".");
          port = parseInt(parts[1]);
        } else if (startsWith(nextCommand,"busy ")) {
          var parts = nextCommand.split(" ");
          myIP = parts[1];
          
          var id:String = null;
          if (gr != null) {
            id = gr.testid;
          }
          handleFatalError("Server busy", "id=" + id
            + "&msg=Server%20busy&busy=1&", 1);
          return;
        } else {
          trace("Unknown response from server:" + nextCommand
            + ".");
          runNextFlow();
          return;
        }
        
        trace("about to setupSocket:"+serverIp);
        // Now connecting to the server for test run        
        sChannel = setupSocket(serverIp, port);
        
      
        // Reset
        lastState = -1;
        bytesTransmitted = 0;
        bytesReceived = 0;
        end = null;
        
        trace("Running "
          + (sendControlFlow ? "control flow for " : "") + proto + " as "
          + (isServer ? "server" : "client") + " on port " + port + '.');
        addToBound((int) (timeout / 1000.0));
        start = getTimer();
        runTransfer(sChannel, proto, timeout, isServer, sendControlFlow, function(transferSuccessful:Boolean) {
          if (end == 0)
            end = getTimer();
          
          var timespan:Number = (end - start) / 1000.0;
          if (timespan < 0)
            timespan = 0;
          
          // Save the following info:
          // - Server port, direction (who acted as server?), protocol
          // - bytes sent
          // - bytes received
          // - timespan in millisecond granularity
          // - lastState
          // - Reset?
          
          results += "expu" + exp + '=' + bytesTransmitted + "&expd" + exp + '='
            + bytesReceived + "&expl" + exp + '=' + timespan + "&expstate"
            + exp + '=' + lastState + '&';
          results += "expp" + exp + '=' + port + "&expprot" + exp + '=' + proto
            + (sendControlFlow ? "-cf" : "") + "&expserv" + exp + '='
            + (isServer ? "client" : "server") + '&';
          
          if (reset) {
            results += "expr" + exp + "=1&";
            trace("FAILED: " + proto + " transfer reset.");
            backLog += "Transfer reset in state " + lastState + " .\n";
          } else if (!transferSuccessful) {
            trace("FAILED: " + proto + " transfer as "
              + (isServer ? "server" : "client") + " failed.");
          }
          trace("Transferred " + bytesTransmitted
            + " bytes and received " + bytesReceived + " bytes in " + timespan
            + " seconds: "
            + ((timespan > 0) ? (bytesTransmitted * 8 / timespan) : 0) + ' '
            + ((timespan > 0) ? (bytesReceived * 8 / timespan) : 0)
            + " bps (state=" + lastState + ')');
          backLog += "Transferred " + bytesTransmitted + " bytes and received "
            + bytesReceived + " bytes in " + timespan + " seconds: "
            + ((timespan > 0) ? (bytesTransmitted * 8 / timespan) : 0) + ' '
            + ((timespan > 0) ? (bytesReceived * 8 / timespan) : 0)
            + " bps (state=" + lastState + ")\n";
          
          exp++; // Next transfer
          
          var outCommand:String = "";
          if (backLog.length > 0) {
            var part = backLog.split("\n");
            
            try {
              for (var i:int = 0; i < part.length; i++) {
                if (part[i].length() == 0)
                  continue;
                
                outCommand += "log ";
                outCommand += part[i];
                outCommand += "\n";
              }
            } catch (e2:Error) {
              return;
            }
            try {
              // System.out.print("Sending log: " + backLog);
              commandChannel.writeUTFBytes(outCommand);
              commandChannel.flush();
            } catch (e2:Error) {
              // trace("Cannot send log to server.");
              var id:String = null;
              if (gr != null) {
                id = gr.testid;
              }
              handleFatalError("Server failed", "id=" + id
                + "&msg=Server%20failed&mid=11", 31, e2);
              return;
            }
            outCommand = "";
            backLog = "";
          }
          
          sChannel.close();
          // Sleep X seconds and give the server some time to prepare for the next
          // round and to drain queues
          setTimeout(runNextFlow, Pause);
        });
      });    
    }
  }
  
  /**
   * bottom of applet run 
   */
  function shutdown() {
    var commandStr:String = "";
    commandStr += "log Sysinfo: ";
    commandStr += GlasnostReplayer.sysinfo;
    commandStr += "\n";
      
    commandStr += "log http ";
    commandStr += results;
    var extra:String = "peer=" + myIP + "&hostname=" + myHostname + "&done=yes&";
    if (specInJar)
      extra += "internal=1&";
    if (gr != null)
      extra += "id=" + gr.testid + "&server=" + gr.mServer + "&port=" + gr.mPort[0] + "&port2=" + gr.mPort[1] + '&' + gr.expParam;
    commandStr += extra;
    commandStr += "\n";
      
    commandStr += "shutdown \n";
    
    commandChannel.writeUTFBytes(commandStr);
    commandChannel.flush();

    // Wait for a final OK, giving the server time to finish its business
    // The server also sends aggregated results here
      /*
      * boolean connectionTerminated = false; while(!connectionTerminated){
      * int ret = commandChannel.read(inCommand);
      * 
      * if (ret < 0) {
      * //trace("Cannot read from command socket");
      * connectionTerminated = true; break; }
      * 
      * String[] part = (new String(inCommand.array(), 0,
      * inCommand.position())).split("\n"); for(int i=0; i<part.length; i++){
      * if(part[i].equals("ok")){ // OK on its own line terminates the
      * connection connectionTerminated = true;
      * trace("Server responded with OK."); break; } } }
      * 
      * // Finally close the command channel commandChannel.close();
      * 
      * String nextCommand = new String(inCommand.array(), 0,
      * inCommand.position()); inCommand.clear();
      * 
      * String[] part = nextCommand.split("\n");
      * 
      * for(int i=0; i<part.length; i++){ if(!part[i].equals("ok")){
      * serverResults += part[i]; } }
      */
      
    serverResults = "";    
    readNextCommand(readNextCommandLoop);
  }
  
  var serverResults:String = "";

  
  function readNextCommandLoop(nextCommand:String):void {
    if (startsWith(nextCommand,"ok")) {
      sendResultsToServer();
      return;
    }
    if (startsWith(nextCommand,"log ")) {
      serverResults += nextCommand.substring(4,nextCommand.length);
    } else {
      serverResults += "unknown=" + nextCommand + '&';
    }
  } // Ignore at this point

  function sendResultsToServer() {
    // We are done, send back results to webserver
    if (gr != null) {
      gr.displayResultPage("peer=" + myIP + "&hostname=" + myHostname + '&'
        + results + '&' + serverResults);
      gr.finished = true;
      gr.rpw = null;
    } else {
      trace("peer=" + myIP + "&hostname=" + myHostname + '&'
        + results + '&' + serverResults);
    }
  }
  
  
  
  function initialCommunicationAndSetup(commandChannel:Socket):void {
    readNextCommand(function(nextCommand:String):void {
      trace(nextCommand);
      if (startsWith(nextCommand, "ip ") && (myIP == null)) {
        var parts:Array = nextCommand.split(" ");
        myIP = parts[1];
        
        trace("Server told me that my external IP is " + myIP);
        
        if (parts.length >= 3)
          myHostname = parts[2];
        
        if ((parts.length >= 5) && (parts[3] == "id")) {
          if (gr != null)
            gr.testid = parts[4];
          
          trace("Test ID is " + parts[4]);
        }        
      } else if (startsWith(nextCommand, "busy ")) {
        var parts:Array = nextCommand.split(" ");
        myIP = parts[1];
        
        var id:String = null;
        if (gr != null) {
          id = gr.testid;
        }
        handleFatalError("Server busy", "id=" + id + "&msg=Server%20busy&busy=1&", 1);
      } else {
        trace("Unknown response from server:" + nextCommand + ".");
      }
      
      var commandStr:String = null;
      // If the script file is located remotely, advice the server to load it
      if (startsWith(scriptFile, "http") || startsWith(scriptFile, "https")) {
        handleFatalError("Not Implemented", "Cant handle remote script", 1);
      }
      
      // Check whether the servers knows all the protocols I want to run
      if (protocol.length <= 0) {
        throw new Error("No protocols selected.");
      }
      commandStr = "protos " + protocol[0];
      for (var i:int = 1; i < protocol.length; i++) {
        if (protocol[i] != "none")
          commandStr += ';' + protocol[i];
      }
      commandStr += "\n";
      
      gr.printItem("Asking server about:"+commandStr);
      trace("Asking server about:"+commandStr);
      commandChannel.writeUTFBytes(commandStr);
      commandChannel.flush();
      trace("Done writing");
      
      readNextCommand(function(nextCommand:String):void {
        if (startsWith(nextCommand, "ok")) {
          trace("Server knows all the protocols I want to replay!");
          gr.printItem("Server knows all the protocols I want to replay!");
          runNextFlow();
        }
      });
    });
  }
  
  private function handleFatalError(message:String, errorParams:String, errorCode:int, e:Error=null):void {
    trace(message+" "+errorParams);
    
    isTerminated = true;

    if ((gr != null) && (errorParams != null)) {
      if (gr.rpw != null)
        gr.rpw.isTerminated = true;
      gr.printItem(message);

      // Encode text
      var sysinfo = GlasnostReplayer.sysinfo;
      var part;
      if (sysinfo != "") {
        part = sysinfo.split(" ");
        sysinfo = "sysinfo=" + part[0];
        for (var i:int = 1; i < part.length; i++) {
          sysinfo += "%20" + part[i];
        }
      }
      var exception:String = "";
      if (e != null) {
        var eMsg:String = e.getMessage();
        if ((eMsg != null) && eMsg != "") {
          part = eMsg.split(" ");
          exception = "exception=" + part[0];
          for (var i:int = 1; i < part.length; i++) {
            exception += "%20" + part[i];
          }
        }
      }
      
      var nextPageStr:String = null;
      if (endsWith(gr.nextPage, "&")) {
        nextPageStr = "http://" + gr.nextPage + "error=1&" + errorParams
          + "&peer=" + myIP + '&' + exception + '&' + sysinfo
          + "&server=" + gr.mServer + "&port=" + gr.mPort[0] + "&port2="
          + gr.mPort[1] + '&' + gr.expParam;
      } else {
        nextPageStr = "http://" + gr.nextPage + "?error=1&" + errorParams
          + "&peer=" + myIP + '&' + exception + '&' + sysinfo
          + "&server=" + gr.mServer + "&port=" + gr.mPort[0] + "&port2="
          + gr.mPort[1] + '&' + gr.expParam;
      }      
      gr.displayResultPage(nextPageStr); // Go to a special error handling
    }
  }
  
  function assert(condition:Boolean):void {
    if (condition) {
      return;
    }
    throw new Error("Assert failed");
  }
  
  
}    
  

class GlasnostCommand {
  public var type:CommandType;
  public static const integerLength:int = 4; // bytes in an integer

  
  public function GlasnostCommand(type:CommandType) {
    this.type = type;    
  }
  
  static function readToColon(stream:ByteArray):ByteArray {
    var buf:ByteArray = new ByteArray();
    while (true) {
      var b:int = stream.readByte();
      
      if (b < 0)
        throw new Error("readToColon: could not find colon");
      
      if (b != 58) {
        buf.writeByte(b);
      } else {
        break;
      }
    }
    buf.position = 0;
    return buf;
  }
}

class EndPoint {
  public static const SERVER:EndPoint = new EndPoint("SERVER");
  public static const CLIENT:EndPoint = new EndPoint("CLIENT");

  private var type:String;
  
  public function EndPoint(type:String) {
    this.type = type;
  }
  
  public function toString():String {
    return type;        
  }

}

class CommandType {
  public static const SEND = new CommandType();
  public static const GOTO = new CommandType();
  public static const PAUSE = new CommandType();
  public static const START_MEASURING = new CommandType();
}

class PayloadType {
  public static const PREV_MSG = new PayloadType("PREV_MSG");
  public static const DATA = new PayloadType("DATA");
  public static const RANDOM = new PayloadType("RANDOM");
  public static const RANDINT = new PayloadType("RANDINT");
  public static const REPEAT = new PayloadType("REPEAT");
  
  
  private var type:String;
  
  public function PayloadType(type:String) {
    this.type = type;
  }
  
  public function toString():String {
    return type;        
  }
}

class PayloadElement {

  public var type:PayloadType = PayloadType.DATA;
  public var n:int  = 0;
  public var k:int = 0;
  var data:ByteArray = null;
  
  public function toString(): String {
    return type.toString()+" n:"+n+" k:"+k+" data:"+data;
  }
  
  public function PayloadElement(stream:ByteArray) {
    var buf:ByteArray = null;
    
    buf = GlasnostCommand.readToColon(stream);
    
    var type_des:String = buf.toString();
    if (type_des == "PREVMSG") {
      this.type = PayloadType.PREV_MSG;
      
    } else if (type_des == "DATA") {
      this.type = PayloadType.DATA;
      buf = GlasnostCommand.readToColon(stream);
      
      var len:int = parseInt(buf.toString());
      data = new ByteArray();
      stream.readBytes(data,0,len);
      data.position = 0;
      
      if (stream.readByte() != 58)
        throw new Error(
          "unable to create PayloadElement: no colon at the end of data section");
      
    } else if (type_des == "RANDOM") {
      this.type = PayloadType.RANDOM;
      
    } else if (type_des == "RANDINT") {
      this.type = PayloadType.RANDINT;
      
    } else if (type_des == "REPEAT") {
      this.type = PayloadType.REPEAT;
      
    } else
      // uknown type
      throw new Error("unable to create PayloadElement: unknown type "
        + type_des);
    
    if (this.type == PayloadType.RANDINT || this.type == PayloadType.PREV_MSG || this.type == PayloadType.REPEAT) {
      buf = GlasnostCommand.readToColon(stream);
      n = parseInt(buf.toString());
      buf = GlasnostCommand.readToColon(stream);
      k = parseInt(buf.toString());
      
    } else if (this.type == PayloadType.RANDOM) {
      buf = GlasnostCommand.readToColon(stream);
      n = parseInt(buf.toString());
      
    }
  }
  
  public function byteLength():int {
    if (this.type == PayloadType.DATA)
      return data.length;
    if (this.type == PayloadType.PREV_MSG)
      return k;
    if (this.type == PayloadType.RANDOM)
      return n;
    if (this.type == PayloadType.RANDINT)
      return GlasnostCommand.integerLength;
    if (this.type == PayloadType.REPEAT)
      return k;
    
    return 0;
  }

}

class SendCommand extends GlasnostCommand {
  public var endpoint:EndPoint;
  public var payload:Vector.<PayloadElement> = new Vector.<PayloadElement>();
  public var length:int = 0;
  
  public function SendCommand(stream:ByteArray) {
    super(CommandType.SEND);
    
    var buf:ByteArray = null;
    
    buf = GlasnostCommand.readToColon(stream);
    
    var endp_str:String = buf.toString();
    if (endp_str == "SERVER")
      this.endpoint = EndPoint.SERVER;
    else if (endp_str == "CLIENT")
      this.endpoint = EndPoint.CLIENT;
    else
      throw new Error("unable to create SendCommand: unknown endpoint " + endp_str);
    
    buf = GlasnostCommand.readToColon(stream);
    var len:int = parseInt(buf.toString()); // number of payload elements to decode
    this.length = 0; // length in bytes of this send command's payload
    for (var i:int = 0; i < len; ++i) {
      var new_el:PayloadElement = new PayloadElement(stream);
      this.payload.push(new_el);
      this.length += new_el.byteLength();
    }
  }
  
  public function toString():String { 
    return "SendCommand<len:"+length+" "+endpoint+" payload:"+payload.length+">";
  }
}

class PauseCommand extends GlasnostCommand {
  public var endpoint:EndPoint;
  public var sec:int = 0;
  public var usec:int = 0;

  public function PauseCommand(stream:ByteArray) {
    super(CommandType.PAUSE);
    
    var buf:ByteArray = null;
    
    buf = GlasnostCommand.readToColon(stream);
    var endp_str:String = buf.toString();
    if (endp_str == "SERVER")
      this.endpoint = EndPoint.SERVER;
    else if (endp_str == "CLIENT")
      this.endpoint = EndPoint.CLIENT;
    else
      throw new Error("unable to create PauseCommand: unknown endpoint " + endp_str);
    
    buf = GlasnostCommand.readToColon(stream);
    this.sec = parseInt(buf.toString()); 
    buf = GlasnostCommand.readToColon(stream);
    this.usec = parseInt(buf.toString()); 
  }
}

class StartMeasuringCommand extends GlasnostCommand {  
  public function StartMeasuringCommand() {
    super(CommandType.START_MEASURING);
  }  
}

class GotoCommand extends GlasnostCommand {
  
  var target_command:int;
  
  public function GotoCommand(stream:ByteArray)  {
    super(CommandType.GOTO);
    
    var buf:ByteArray = null;
    
    buf = GlasnostCommand.readToColon(stream);
    this.target_command = parseInt(buf.toString()); 
  }
}










