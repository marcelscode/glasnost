import java.applet.Applet;
import java.applet.AppletContext;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.io.BufferedReader;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.ByteOrder;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Random;
import java.util.Vector;
import java.util.ArrayList;

/**
 * This code functions as a Java Application and a Java Applet. It can replay
 * arbitrary application-level protocols using TCP by replaying protocol
 * specifications.
 * 
 * 
 * How to sign a java applet: - Generate a self-signed certificate: keytool
 * -genkey -alias broadband.mpi-sws.mpg.de - jar the applet jar -cvf applet.jar
 * BlockingDetector*.class - sign the jar jarsigner applet.jar
 * broadband.mpi-sws.mpg.de
 * 
 * 
 * Known Problems: Detecting if a connection was reset is not trivial in Java.
 * Java just throws a IOException if read() or write() fails. We have to parse
 * the Exception text. However, some versions of Java will localize this
 * message.
 * 
 * Known Limitations: The current implementation only allows to run two
 * protocols and two ports at a time.
 * 
 * Note that the maximum duration of a test is 30 seconds (enforced here and in
 * the server part)
 */

// TODO Add functionality to check whether packets were altered in flight
// TODO Allow to just specify the scriptFile ID w/o protocol name (we take this
// from the scriptFile then) -> Currently, the php script works around this

public class GlasnostReplayer extends Applet {

  public static final String VERSION = "28.02.2013";

  public static String sysinfo = "";
  public String nextPage = "bb/failed";
  public String expParam;

  protected ReplayWorker rpw = null;
  protected String mServer;
  protected String mScriptFile = null;
  protected String[] mProtocol = new String[2];
  protected int mPort[] = new int[2];
  protected String testid = "unknown";
  protected boolean up = false, down = false;
  protected int repeat = 2;
  protected int duration = 20;
  protected StringBuffer buffer;

  public boolean finished = false;

  public AppletContext appletContext = null;
  private boolean browserWorkaround = false;

  protected static int done = 0;
  protected int totalLength = 100;

  private static abstract class GlasnostCommand {

    public static int integerLength = 4; // bytes in an integer

    public static byte[] readToColon(InputStream stream) throws Exception {

      ByteArrayOutputStream buf = new ByteArrayOutputStream();
      while (true) {
        int b = stream.read();
        // DEBUG
        // System.out.print((char)b);

        if (b < 0)
          throw new Exception("readToColon: could not find colon");

        if (b != 58) {
          buf.write(b);
        } else {
          break;
        }
      }
      return buf.toByteArray();
    }

    public enum CommandType {
      SEND, GOTO, PAUSE, START_MEASURING
    }

    public enum EndPoint {
      SERVER, CLIENT
    }

    public CommandType type;

    public GlasnostCommand(CommandType type) {
      this.type = type;
    }

  }

  private static class PayloadElement {

    public enum PayloadType {
      PREV_MSG, DATA, RANDOM, RANDINT, REPEAT
    };

    public PayloadType type = PayloadType.DATA;
    public int n = 0;
    public int k = 0;

    public ByteArrayOutputStream data;

    public PayloadElement() {
    }

    public String toString() {
      return type+" n:"+n+" k:"+k+" data:"+data;
    }
    
    public int byteLength() {

      if (this.type == PayloadType.DATA)
        return data.size();
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

    public PayloadElement(InputStream stream) throws Exception {

      byte[] buf = GlasnostCommand.readToColon(stream);

      String type_des = new String(buf, "US-ASCII");
      if (type_des.equals("PREVMSG")) {
        this.type = PayloadType.PREV_MSG;

      } else if (type_des.equals("DATA")) {
        this.type = PayloadType.DATA;
        buf = GlasnostCommand.readToColon(stream);

        int len = Integer.decode(new String(buf, "US-ASCII"));
        data = new ByteArrayOutputStream();
        for (int n = 1; n <= len; ++n) {
          int b = stream.read();
          if (b < 0)
            throw new Exception(
                "unable to create PayloadElement: not enough bytes (needed="
                    + len + ", found=" + n + ")");
          data.write(b);
        }

        if (stream.read() != 58)
          throw new Exception(
              "unable to create PayloadElement: no colon at the end of data section");

      } else if (type_des.equals("RANDOM")) {
        this.type = PayloadType.RANDOM;

      } else if (type_des.equals("RANDINT")) {
        this.type = PayloadType.RANDINT;
      } else if (type_des.equals("REPEAT")) {
        this.type = PayloadType.REPEAT;

      } else
        // uknown type
        throw new Exception("unable to create PayloadElement: unknown type "
            + type_des);

      if (this.type == PayloadType.RANDINT || this.type == PayloadType.PREV_MSG
          || this.type == PayloadType.REPEAT) {
        buf = GlasnostCommand.readToColon(stream);
        n = Integer.decode(new String(buf, "US-ASCII"));
        buf = GlasnostCommand.readToColon(stream);
        k = Integer.decode(new String(buf, "US-ASCII"));

      } else if (this.type == PayloadType.RANDOM) {
        buf = GlasnostCommand.readToColon(stream);
        n = Integer.decode(new String(buf, "US-ASCII"));

      }
    }

  }

  private static class SendCommand extends GlasnostCommand {

    public EndPoint endpoint;
    public ArrayList<PayloadElement> payload = new ArrayList<PayloadElement>();
    public int length = 0;

    public SendCommand(EndPoint endpoint) {
      super(CommandType.SEND);
      this.endpoint = endpoint;
    }

    public SendCommand(InputStream stream) throws Exception {
      super(CommandType.SEND);

      byte[] buf = GlasnostCommand.readToColon(stream);

      String endp_str = new String(buf, "US-ASCII");
      if (endp_str.equals("SERVER"))
        this.endpoint = EndPoint.SERVER;
      else if (endp_str.equals("CLIENT"))
        this.endpoint = EndPoint.CLIENT;
      else
        throw new Exception("unable to create SendCommand: unknown endpoint "
            + endp_str);

      buf = GlasnostCommand.readToColon(stream);
      int len = Integer.decode(new String(buf, "US-ASCII")); // number of
                                                             // payload elements
                                                             // to decode
      this.length = 0; // length in bytes of this send command's payload
      for (int i = 0; i < len; ++i) {
        PayloadElement new_el = new PayloadElement(stream);
        this.payload.add(new_el);
        this.length += new_el.byteLength();
      }      
    }
    
    public String toString() {
      return "SendCommand<len:"+length+" "+endpoint+" payload:"+payload.size()+">";
    }

    public void appendDataPayload(byte[] data) throws IOException {
      this.length += data.length;
      if (!payload.isEmpty()) {
        PayloadElement last_el = payload.get(payload.size() - 1);
        if (last_el.type == PayloadElement.PayloadType.DATA) {
          last_el.data.write(data);
          return;
        }
      }
      PayloadElement new_el = new PayloadElement();
      new_el.data = new ByteArrayOutputStream();
      new_el.type = PayloadElement.PayloadType.DATA;
      new_el.data.write(data);
      payload.add(new_el);
    }

    public void appendRandintPayload(int low, int high) {

      length += integerLength;
      PayloadElement new_el = new PayloadElement();
      new_el.type = PayloadElement.PayloadType.RANDINT;
      new_el.n = low;
      new_el.k = high;
      payload.add(new_el);
    }

    public void appendRandomPayload(int length) {

      length += length;
      PayloadElement new_el = new PayloadElement();
      new_el.type = PayloadElement.PayloadType.RANDOM;
      new_el.n = length;
      payload.add(new_el);
    }

    public void appendRepeatPayload(int val, int repeat) {

      length += repeat;
      PayloadElement new_el = new PayloadElement();
      new_el.type = PayloadElement.PayloadType.REPEAT;
      new_el.n = val;
      new_el.k = repeat;
      payload.add(new_el);
    }

    public void appendPrevmsgPayload(int offset, int length) {

      length += length;
      PayloadElement new_el = new PayloadElement();
      new_el.type = PayloadElement.PayloadType.PREV_MSG;
      new_el.n = offset;
      new_el.k = length;
      payload.add(new_el);
    }

  }

  public static class GotoCommand extends GlasnostCommand {

    int target_command;

    public GotoCommand(int target) {
      super(CommandType.GOTO);
      this.target_command = target;
    }

    public GotoCommand(InputStream stream) throws Exception {
      super(CommandType.GOTO);

      byte[] buf = GlasnostCommand.readToColon(stream);
      this.target_command = Integer.decode(new String(buf, "US-ASCII"));
    }
  }

  public static class StartMeasuringCommand extends GlasnostCommand {

    public StartMeasuringCommand() {
      super(CommandType.START_MEASURING);
    }

  }

  public static class PauseCommand extends GlasnostCommand {

    EndPoint endpoint;
    int sec;
    int usec;

    public PauseCommand(EndPoint endpoint, int sec, int usec) {
      super(CommandType.PAUSE);
      this.endpoint = endpoint;
      this.sec = sec;
      this.usec = usec;
    }

    public PauseCommand(InputStream stream) throws Exception {
      super(CommandType.PAUSE);

      byte[] buf = GlasnostCommand.readToColon(stream);
      String endp_str = new String(buf, "US-ASCII");
      if (endp_str.equals("SERVER"))
        this.endpoint = EndPoint.SERVER;
      else if (endp_str.equals("CLIENT"))
        this.endpoint = EndPoint.CLIENT;
      else
        throw new Exception("unable to create PauseCommand: unknown endpoint "
            + endp_str);

      buf = GlasnostCommand.readToColon(stream);
      this.sec = Integer.decode(new String(buf, "US-ASCII"));
      buf = GlasnostCommand.readToColon(stream);
      this.usec = Integer.decode(new String(buf, "US-ASCII"));
    }

  }

  public static class GlasnostScript {

    String protocol;
    int[] port = new int[0];
    int duration = 0; // in milliseconds!

    ArrayList<GlasnostCommand> commands = new ArrayList<GlasnostCommand>();

    public GlasnostScript(InputStream stream) throws Exception {

      byte[] buf = GlasnostCommand.readToColon(stream);
      String label = new String(buf, "US-ASCII");
      int p;
      if (!label.equals("PROTO"))
        throw new Exception(
            "could not create GlasnostScript, expected PROTO, found " + label);
      buf = GlasnostCommand.readToColon(stream);
      this.protocol = new String(buf, "US-ASCII");

      IntBuffer found_ports = IntBuffer.allocate(2);

      buf = GlasnostCommand.readToColon(stream);
      label = new String(buf, "US-ASCII");
      if (!label.equals("PORT1"))
        throw new Exception(
            "could not create GlasnostScript, expected PORT1, found " + label);
      buf = GlasnostCommand.readToColon(stream);
      p = Integer.decode(new String(buf, "US-ASCII"));
      if (p > 0)
        found_ports.put(p);

      buf = GlasnostCommand.readToColon(stream);
      label = new String(buf, "US-ASCII");
      if (!label.equals("PORT2"))
        throw new Exception(
            "could not create GlasnostScript, expected PORT2, found " + label);
      buf = GlasnostCommand.readToColon(stream);
      p = Integer.decode(new String(buf, "US-ASCII"));
      if (p > 0)
        found_ports.put(p);

      port = found_ports.array();

      buf = GlasnostCommand.readToColon(stream);
      label = new String(buf, "US-ASCII");
      if (!label.equals("DURATION"))
        throw new Exception(
            "could not create GlasnostScript, expected DURATION, found "
                + label);
      buf = GlasnostCommand.readToColon(stream);
      this.duration = Integer.decode(new String(buf, "US-ASCII")) * 1000;

      buf = GlasnostCommand.readToColon(stream);
      int com = Integer.decode(new String(buf, "US-ASCII"));

      for (int i = 0; i < com; ++i) {

        GlasnostCommand new_com = null;
        buf = GlasnostCommand.readToColon(stream);
        String type = new String(buf, "US-ASCII");
        if (type.equals("SEND"))
          new_com = new SendCommand(stream);
        else if (type.equals("PAUSE"))
          new_com = new PauseCommand(stream);
        else if (type.equals("START_MEASURING"))
          new_com = new StartMeasuringCommand();
        else if (type.equals("GOTO"))
          new_com = new GotoCommand(stream);

        this.commands.add(new_com);
      }

    }
  }

  /**
   * Thread that is used to calculate and display a progress bar to show the
   * finish time of the measurement
   */

  private static class Countdown extends Thread {
    private GlasnostReplayer parent = null;
    private long startTime;
    private long endTime;
    private int totalLength;
    private int bound;
    private int timeLeft;
    private boolean stalled = false;
    public boolean isTerminated = false;

    public Countdown(GlasnostReplayer p, int totalLength) {
      super();
      this.startTime = System.currentTimeMillis();
      this.parent = p;
      this.totalLength = totalLength;
      this.bound = 0;
      this.timeLeft = totalLength;
    }

    public void setBound(int newBound) {
      this.bound = newBound;
      endTime = (timeLeft * 1000) + System.currentTimeMillis();
    }

    public void addToBound(int addBound) {
      this.bound += addBound;
      endTime = (timeLeft * 1000) + System.currentTimeMillis();
    }

    public void run() {
      endTime = startTime + (totalLength * 1000);

      while (!isTerminated && (endTime > System.currentTimeMillis())) {

        timeLeft = (int) ((endTime - System.currentTimeMillis()) / 1000.0);
        if (timeLeft < (totalLength - bound)) {
          timeLeft = totalLength - bound;
          stalled = !stalled;
        } else
          stalled = false;

        done = (int) (totalLength - timeLeft);
        if (!parent.finished) {

          if (!stalled)
            parent.printItem("Time to finish: " + String.valueOf(timeLeft)
                + " seconds");
          else
            parent.printItem("Waiting for transfer to finish.");
        }
        try {
          sleep(1000);
        } catch (InterruptedException e) {
        }
      }

      done = (int) totalLength;
      if (!parent.finished)
        parent.printItem("Processing data...");
    }
  }

  private static class ReplayWorker extends Thread {

    private static final long ConnectTimeout = 20000;
    private static final int DefaultDuration = 10000;
    private static final int MaximumDuration = 30000;
    private static final long Pause = 500; // in milliseconds - time between two
                                           // experiments

    protected GlasnostReplayer gr = null;
    protected Countdown cd = null;

    private final int commandPort = 19970;

    protected String myIP = null;
    protected String myHostname = null;
    protected String serverIP = null;
    protected int serverPort[] = new int[2];
    protected String[] protocol;
    protected InetSocketAddress local = null;

    private String scriptFile = "protocols.spec.marshalled";
    private boolean specInJar = true;
    // HashMap<String, Vector<String>> protocolScript = new HashMap<String,
    // Vector<String>>();
    // HashMap<String, int[]> protocolPort = new HashMap<String, int[]>();
    // HashMap<String, Long> protocolDuration = new HashMap<String, Long>();

    HashMap<String, GlasnostScript> protocolScript = new HashMap<String, GlasnostScript>();

    protected long duration = -1; // in milliseconds
    private int totalDuration = 0; // in seconds

    protected boolean isTerminated = false;
    protected boolean reset = false;
    protected long start, end;
    protected int lastState;
    protected long bytesTransmitted = 0;
    protected long bytesReceived = 0;

    // Control variables
    protected int numberOfRepeats = 1;
    protected int[] upstream = new int[2];
    protected int[] downstream = new int[2];

    private PrintStream log = null;
    private String backLog = "";
    private Random rnd;

    private final int bufSizeBytes = 11 * 2048576;
    private String errorMsg = null; // Debug

    /**
     * Reads in a Glasnost script file and puts the scripts of the requested
     * protocols as a Vector of Strings into a Hash map (protocolScript)
     * 
     * @param scriptFile
     *          The script file to read, can be remote (via http; give full URL)
     * @param proto
     *          List of protocols that should be read-in
     * @return List of protocols that could not be found. Null otherwise if
     *         there was no problem.
     */
    public String[] readInScript(String scriptFile, String[] proto) {

      assert ((proto != null) && (proto.length > 0));

      // String[] protocol = proto.clone();
      // int numUnknown = protocol.length;
      // Vector<String> currentScript = null;

      BufferedInputStream script = null;
      if (scriptFile.startsWith("http://")) {
        URL url = null;
        try {
          url = new URL(scriptFile);
        } catch (MalformedURLException e) {
          e.printStackTrace();
          return protocol;
        }

        try {
          // script = new BufferedReader(new
          // InputStreamReader(url.openStream()));
          script = new BufferedInputStream(url.openStream());

        } catch (IOException e) {
          String id = null;
          if (gr != null) {
            id = gr.testid;
          }
          handleFatalError("Cannot fetch script file from server", "id=" + id
              + "&msg=script%20fetch%20failed", 6, e);
          return protocol;
        }
      } else {
        try {
          if (specInJar)
            script = new BufferedInputStream(gr.getClass().getResourceAsStream(
                scriptFile));
          else
            script = new BufferedInputStream(new FileInputStream(scriptFile));
        } catch (FileNotFoundException e) {
          String id = null;
          if (gr != null)
            id = gr.testid;

          handleFatalError("Protocol description file " + scriptFile
              + " not found.", "id=" + id
              + "&mid=21&msg=scriptFile%20not%20found&", 6, e);
        }
      }

      if (script == null) {
        String id = null;
        if (gr != null)
          id = gr.testid;
        handleFatalError("Protocol description file " + scriptFile
            + " not found.", "id=" + id
            + "&mid=21&msg=scriptFile%20not%20found", 6);
      }

      // read the scripts and store them into protocolScript
      protocolScript.clear();
      try {
        byte[] buf = GlasnostCommand.readToColon(script);
        int num_of_protos = Integer.decode(new String(buf, "US-ASCII"));
        System.out.println("preparing to read " + num_of_protos + " protocols");

        for (int p = 0; p < num_of_protos; ++p) {
          GlasnostScript gs = new GlasnostScript(script);
          protocolScript.put(gs.protocol, gs);
          System.out.println();
          if (gs != null) {
            System.out.print("found proto " + gs.protocol + " with "
                + gs.commands.size() + " instructions, ports=");
            for (int pn : gs.port) {
              System.out.print(pn + " ");
            }
            System.out.println("duration=" + gs.duration);
          } else {
            System.out.println("could not parse protocol");
          }
        }

      } catch (Exception e) {
        String id = null;
        if (gr != null)
          id = gr.testid;
        System.out.println("While parsing script(s): " + e);
        handleFatalError("Error while parsing the bytecode for " + scriptFile,
            "id=" + id + "&mid=21&msg=bytecode%20for%20scriptFile%20invalid",
            6, e);
      }

      ArrayList<String> unknownProtocol = new ArrayList<String>();
      for (String p : proto) {
        if (!protocolScript.containsKey(p))
          unknownProtocol.add(p);
      }
      return unknownProtocol.toArray(new String[0]);
    }

    public void setFileOutput(String filename) {

      if (filename == null)
        return;

      try {
        log = new PrintStream(new FileOutputStream(filename), true);

        System.setOut(log);
        System.setErr(log);

      } catch (FileNotFoundException e) {
        System.err.println("Cannot open file " + filename);
        e.printStackTrace();
        log = null;
        return;
      }
    }

    public boolean setProtocols(String[] proto) {

      if (protocolScript.isEmpty()) {
        String[] unknownProtocol = readInScript(scriptFile, proto);

        if ((unknownProtocol != null) && (unknownProtocol.length > 0)) {

          System.err.print("Error: Cannot find " + unknownProtocol.length
              + " protocol(s) in file " + scriptFile + ':');
          for (int i = 0; i < unknownProtocol.length; i++)
            System.err.print(' ' + unknownProtocol[i]);
          System.err.println();

          return false;
        }
      } else {
        String[] proto_t = proto.clone();
        int numUnknown = proto_t.length;

        for (int i = 0; i < proto_t.length; i++) {
          if (proto_t[i] == null)
            continue;
          else if (protocolScript.containsKey(proto_t[i])
              || proto_t[i].equals("none")) {
            proto_t[i] = null;
            numUnknown--;
          }
        }

        if (numUnknown > 0) {
          System.err
              .print("Error! Cannot find the following protocol(s) in file "
                  + scriptFile + ':');
          for (int i = 0; i < proto_t.length; i++) {
            if (proto_t[i] != null)
              System.err.print(' ' + proto_t[i]);
          }
          System.err.println();

          return false;
        }
      }

      this.protocol = new String[proto.length];
      for (int i = 0; i < proto.length; i++)
        this.protocol[i] = proto[i];

      return true;
    }

    private void init() {
      rnd = new Random();
    }

    public ReplayWorker(String serverIP, String scriptFile, String[] protocol,
        int[] port, GlasnostReplayer gr) throws Exception {

      this(serverIP, scriptFile, false, protocol, port, gr);
    }

    public ReplayWorker(String serverIP, String scriptFile, String[] protocol,
        int[] port) throws Exception {

      this(serverIP, scriptFile, false, protocol, port, null);
    }

    public ReplayWorker(String serverIP, String scriptFile, boolean specInJar,
        String[] protocol, int[] port) throws Exception {

      this(serverIP, scriptFile, specInJar, protocol, port, null);
    }

    public ReplayWorker(String serverIP, String scriptFile, boolean specInJar,
        String[] protocol, int[] port, GlasnostReplayer gr) throws Exception {

      assert ((serverIP != null) && (protocol != null) && (port != null));
      assert ((protocol.length > 0) && (port.length > 0));

      this.serverIP = serverIP;

      if (scriptFile != null) {
        this.scriptFile = scriptFile;
        this.specInJar = specInJar;
      }
      this.gr = gr;

      if (this.specInJar)
        System.out.println("Using internal script file " + this.scriptFile);
      else
        System.out.println("Using script file " + this.scriptFile);

      if (!setProtocols(protocol)) {
        String id = null;
        if (gr != null)
          id = gr.testid;

        handleFatalError("Protocols not found in file " + this.scriptFile,
            "id=" + id + "&mid=21&msg=protocols%20not%20found", 6); // FATAL!
        throw new Exception("Test not found");
      }

      for (int i = 0; i < Math.min(2, port.length); i++)
        // Only support two ports for the moment
        this.serverPort[i] = port[i];

      init();
    }

    /**
     * Given command line parameters, calculate how long the whole measurement
     * run will take and set up the internal variables to control the
     * measurement
     */
    public void initalSetup(boolean up, boolean down, int repeat, int duration) {

      if (repeat > 0)
        this.numberOfRepeats = repeat;
      if (duration > 0) {
        this.duration = duration * 1000;
      }

      if (up) {
        upstream[0] += repeat;
        if ((protocol.length == 1)
            || ((protocol.length > 1) && !protocol[1].equals("none"))) {
          upstream[1] += repeat;
          totalDuration += 10; // For socket warm-up
        }
      }
      if (down) {
        downstream[0] += repeat;
        if ((protocol.length == 1)
            || ((protocol.length > 1) && !protocol[1].equals("none"))) {
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

      long d = this.duration;
      if (d <= 0)
        d = DefaultDuration; // Will be set later, so use this default value
                             // here

      totalDuration += (int) ((Pause + d) / 1000)
          * (upstream[0] + upstream[1] + downstream[0] + downstream[1]);

      if (gr != null) {
        cd = new Countdown(gr, totalDuration);
        gr.totalLength = totalDuration;
        cd.start();
      }
    }

    /**
     * Creates a non-blocking SocketChannel with ReuseAddress set
     * 
     * @param peer
     *          The server to connect to
     * @param selector
     *          An existing selector
     * @param timeout
     *          The socket timeout in millis
     * @return
     */
    public SocketChannel setupSocket(InetSocketAddress peer, Selector selector,
        int timeout) {
      log(System.out,"setupSocket("+peer.getAddress()+","+peer.getPort()+")");
      assert (selector != null);

      SocketChannel sChannel = null;
      Socket socket = null;

      System.out.println("Connecting to " + peer.getAddress().toString()
          + " on port " + peer.getPort());

      /*
       * if(local != null) { try{ local = new
       * InetSocketAddress(local.getPort()+1); } catch (IllegalArgumentException
       * e) { local = null; } }
       */

      try {
        sChannel = SocketChannel.open();
        sChannel.configureBlocking(false);
        socket = sChannel.socket();
        socket.setReuseAddress(true);
      } catch (IOException e2) {
        System.err.println("Failed to create new socket: " + e2);
        e2.printStackTrace();
        handleFatalError("Cannot create socket", "id=" + gr.testid
            + "&msg=Cannot%20create%20socket", 8);

        errorMsg = "Failed to create new socket: " + e2.getMessage();
        return null;
      }

      try {
        socket.setSoTimeout(timeout);

        // Setting the TCP_NODELAY option here disable Nagle's algorithm for the
        // socket
        // What this means is that the TCP socket will NOT wait until it buffers
        // MSS bytes before
        // sending a packet. This is needed to faithfuly replay a trace where
        // packets smaller than MSS
        // are sent. Unfortunately, it's not enough to preserve the packets of
        // the original trace, becaause
        // messages are still buffered by the socket when no packet can be sent
        // and then sent later breaking the message boundaries
        socket.setTcpNoDelay(true);
        log(System.out, "Enabling TCP_NODELAY option for socket");

        if (local != null)
          sChannel.socket().bind(local);
        sChannel.connect(peer);

      } catch (IOException e) {
        if (gr != null)
          gr.printItem("Cannot connect to " + peer.toString());
        System.err.println("Cannot connect to " + peer.toString() + ". " + e);

        errorMsg = "Cannot connect to server.";
        return null;
      }

      SelectionKey selKey = null;
      try {
        selKey = sChannel.register(selector, SelectionKey.OP_CONNECT);
      } catch (ClosedChannelException e) {
        System.err.println("Cannot register socket with select: " + e);
        e.printStackTrace();
        String id = null;
        if (gr != null) {
          id = gr.testid;
        }
        try {
          sChannel.close();
        } catch (IOException e1) {
        }

        handleFatalError("Internal error", "id=" + id
            + "&msg=register%20failed", 8, e);
        return null;
      }

      // Wait at most ConnectTimeout milliseconds for a connection
      int numReady = -1;
      try {
        numReady = selector.select(ConnectTimeout);
      } catch (IOException e) {
        System.err.println("Cannot call select: " + e);
        e.printStackTrace();
        String id = null;
        if (gr != null) {
          id = gr.testid;
        }
        try {
          sChannel.close();
        } catch (IOException e1) {
        }

        handleFatalError("Internal error", "id=" + id + "&msg=select%20failed",
            4, e);
        return null;
      }

      if (numReady > 0) {
        Iterator<SelectionKey> it = selector.selectedKeys().iterator();
        while (it.hasNext()) {
          SelectionKey sKey = (SelectionKey) it.next();
          it.remove();

          /* If the channel is ready to be connected, do so */
          if (sKey.isConnectable()) {

            try {
              sChannel.finishConnect();
            } catch (IOException e) {
              selKey.cancel();
              if (gr != null)
                gr.printItem("Error: Connection to server " + peer.toString()
                    + " failed.");
              System.err
                  .println("SocketException while setting up experimental connection.");
              try {
                sChannel.close();
              } catch (IOException e1) {
              }

              errorMsg = "SocketException in setupSocket: " + e.getMessage();
              return null;
            }
            break;
          }
        }
      } else {
        if (gr != null)
          gr.printItem("Error: Connection to server " + peer.toString()
              + " timed out.");
        System.err.println("Connection timed out.");
        try {
          sChannel.close();
        } catch (IOException e) {
        }
        selKey.cancel();

        errorMsg = "Timeout.";
        return null;
      }

      /*
       * if(local == null) local = new InetSocketAddress(socket.getLocalPort());
       */
      return sChannel;
    }

    public void log(PrintStream stream, String x) {
      stream.println(x);
    }

    int writePacket(SocketChannel sChannel, Selector selector, ByteBuffer obuf,
        long endTime) {
      log(System.out, "writePacket("+(obuf.limit() - obuf.position())+"):"+obuf);
      int wptr = 0;
      boolean connectionClosed = false;
      while ((wptr < obuf.limit()) && !connectionClosed) {

        long now = System.currentTimeMillis();
        if (now >= endTime) {
          log(System.out, "Time is up, ending");
          return wptr;
        }

        long selTimeout = endTime - now;
        int numReady = -1;
        try {
          numReady = selector.select(selTimeout);
        } catch (IOException e) {
          System.err.println("Cannot call select: " + e);
          e.printStackTrace();
          String id = null;
          if (gr != null) {
            id = gr.testid;
          }

          handleFatalError("Internal error", "id=" + id
              + "&msg=select%20failed", 4);
          return wptr;
        }

        if (numReady > 0) {
          Iterator<SelectionKey> it = selector.selectedKeys().iterator();
          while (it.hasNext()) {
            SelectionKey selKey = (SelectionKey) it.next();
            it.remove();

            /* If the channel is ready for writing, do so */

            if (!connectionClosed && selKey.isWritable()) {
              sChannel = (SocketChannel) selKey.channel();

              try {
                int bytesWritten = sChannel.write(obuf);

                if (bytesWritten <= 0) {
                  connectionClosed = true;
                  break;
                }

                wptr += bytesWritten;
              } catch (IOException e) {
                // The channel was closed...
                backLog += "Exception: " + e.getMessage() + "\n";

                /*
                 * Again, we have a problem with localized exception texts (see
                 * comment above)
                 */
                if ((e.getMessage() != null)
                    && (e.getMessage().contains("reset") || e.getMessage()
                        .contains("forcibly"))) {
                  System.err.println("Connection was reset.");
                  reset = true;
                } else {
                  System.err.println("Connection failed: " + e.getMessage());
                }

                selKey.cancel();
                connectionClosed = true;
                if (wptr == 0)
                  return -1;
              }
            }
          }
        } else {
          connectionClosed = true;
          log(System.out, "Time is up, ending (select() timed out: write)");
          break;
        }
      }
      return wptr;
    }

    int readPacket(SocketChannel sChannel, Selector selector, ByteBuffer ibuf,
        long endTime) {
      int rptr = 0;
      boolean connectionClosed = false;
      while ((rptr < ibuf.limit()) && !connectionClosed) {

        long now = System.currentTimeMillis();
        if (now >= endTime) {
          log(System.out, "Time is up, ending");
          return rptr;
        }

        long selTimeout = endTime - now;
        int numReady = -1;
        try {
          numReady = selector.select(selTimeout);
        } catch (IOException e) {
          System.err.println("Cannot call select: " + e);
          e.printStackTrace();
          String id = null;
          if (gr != null) {
            id = gr.testid;
          }

          handleFatalError("Internal error", "id=" + id
              + "&msg=select%20failed", 4);
          return rptr;
        }

        if (numReady > 0) {
          Iterator<SelectionKey> it = selector.selectedKeys().iterator();
          while (it.hasNext()) {
            SelectionKey selKey = (SelectionKey) it.next();
            it.remove();

            /* If the channel is ready for reading, do so */

            if (!connectionClosed && selKey.isReadable()) {
              sChannel = (SocketChannel) selKey.channel();
              
              try {
                int bytesRead = sChannel.read(ibuf);

                if (bytesRead <= 0) {
                  connectionClosed = true;
                  break;
                }

                rptr += bytesRead;
              } catch (IOException e) {

                // The channel was closed...
                backLog += "Exception: " + e.getMessage() + "\n";

                /*
                 * Here we run into a problem: The only way to distinguish
                 * between connection resets and other problems is to parse the
                 * text of the exception. Unfortunately some JVMs localize their
                 * exception messages, so for all we know this might be in
                 * Chinese. We check for English immediately, but we report the
                 * exception message to the server just in case, so we can do
                 * postprocessing.
                 */

                if (e.getMessage().contains("reset")
                    || e.getMessage().contains("forcibly")) {
                  System.err.println("Connection was reset.");
                  reset = true;
                } else {
                  System.err.println("Connection failed: " + e.getMessage());
                }

                selKey.cancel();
                connectionClosed = true;
                if (rptr == 0)
                  return -1;
              }
            }
          }
        } else {
          connectionClosed = true;
          log(System.out, "Time is up, ending (select() timed out: read)");
          break;
        }
      }
      return rptr;
    }

    boolean readAndWritePacket(SocketChannel sChannel, Selector selector,
        ByteBuffer obuf, ByteBuffer ibuf, long endTime) {
      int wptr = 0, rptr = 0;
      boolean connectionClosed = false;
      while ((wptr < obuf.limit()) && (rptr < ibuf.limit())
          && !connectionClosed) {

        long now = System.currentTimeMillis();
        if (now >= endTime) {
          log(System.out, "Time is up, ending");
          return false;
        }

        long selTimeout = endTime - now;
        int numReady = -1;
        try {
          numReady = selector.select(selTimeout);
        } catch (IOException e) {
          System.err.println("Cannot call select: " + e);
          e.printStackTrace();
          String id = null;
          if (gr != null) {
            id = gr.testid;
          }

          handleFatalError("Internal error", "id=" + id
              + "&msg=select%20failed", 4);
          return false;
        }

        if (numReady > 0) {
          Iterator<SelectionKey> it = selector.selectedKeys().iterator();
          while (it.hasNext()) {
            SelectionKey selKey = (SelectionKey) it.next();
            it.remove();

            // If the channel is ready for reading, do so
            if (!connectionClosed && selKey.isReadable()) {
              sChannel = (SocketChannel) selKey.channel();

              try {
                int bytesRead = sChannel.read(ibuf);

                if (bytesRead <= 0) {
                  connectionClosed = true;
                  break;
                }

                rptr += bytesRead;
              } catch (IOException e) {

                // The channel was closed...
                backLog += "Exception: " + e.getMessage() + "\n";

                /*
                 * Here we run into a problem: The only way to distinguish
                 * between connection resets and other problems is to parse the
                 * text of the exception. Unfortunately some JVMs localize their
                 * exception messages, so for all we know this might be in
                 * Chinese. We check for English immediately, but we report the
                 * exception message to the server just in case, so we can do
                 * postprocessing.
                 */

                if (e.getMessage().contains("reset")
                    || e.getMessage().contains("forcibly")) {
                  System.err.println("Connection was reset.");
                  reset = true;
                } else {
                  System.err.println("Connection failed: " + e.getMessage());
                }

                selKey.cancel();
                connectionClosed = true;
                if (rptr == 0)
                  return false;
              }
            }

            // If the channel is ready for writing, do so
            if (!connectionClosed && selKey.isWritable()) {
              sChannel = (SocketChannel) selKey.channel();

              try {
                int bytesWritten = sChannel.write(obuf);

                if (bytesWritten <= 0) {
                  connectionClosed = true;
                  break;
                }

                wptr += bytesWritten;
              } catch (IOException e) {
                // The channel was closed...
                backLog += "Exception: " + e.getMessage() + "\n";

                /*
                 * Again, we have a problem with localized exception texts (see
                 * comment above)
                 */
                if (e.getMessage().contains("reset")
                    || e.getMessage().contains("forcibly")) {
                  System.err.println("Connection was reset.");
                  reset = true;
                } else {
                  System.err.println("Connection failed: " + e.getMessage());
                }

                selKey.cancel();
                connectionClosed = true;
                if (wptr == 0)
                  return false;
              }
            }
          }
        } else {
          connectionClosed = true;
          log(System.out, "Time is up, ending (select() timed out)");
          break;
        }
      }

      return true;
    }

    void createMessage(ByteBuffer buf, ArrayList<PayloadElement> payload,
        ByteBuffer prevmsg) {
      buf.clear();
      buf.order(ByteOrder.BIG_ENDIAN);

      for (PayloadElement p : payload) {
        log(System.out, "createMessage("+p+","+prevmsg+")");

        if (p.type == PayloadElement.PayloadType.DATA) {
          buf.put(p.data.toByteArray());

        } else if (p.type == PayloadElement.PayloadType.PREV_MSG) {
          int offset = p.n;
          int len = p.k;
          if (offset + len > prevmsg.limit()) {
            log(System.err,
                "Size of prevous message exceeded, truncating message (size="
                    + Integer.toString(prevmsg.limit()) + ", offset="
                    + Integer.toString(offset) + ", len="
                    + Integer.toString(len));
            len = prevmsg.limit() - offset;
          }

          for (int i = offset; i < offset + len; ++i)
            buf.put(prevmsg.get(i));

        } else if (p.type == PayloadElement.PayloadType.RANDOM) {

          int len = p.n;
          byte[] rb = new byte[p.n];
          rnd.nextBytes(rb);
          buf.put(rb);

        } else if (p.type == PayloadElement.PayloadType.REPEAT) {

          int len = p.k;
          for (int i = 0; i < len; ++i)
            buf.put((byte) p.n);

        } else if (p.type == PayloadElement.PayloadType.RANDINT) {

          int xmin = p.n;
          int xmax = p.k;
          // this alyways takes 4 bytes in Java
          buf.putInt(xmin + (Math.abs(rnd.nextInt()) % (xmax - xmin + 1)));
        }

      }

      buf.flip();
    }

    /**
     * Run a transfer between client and server. The protocol to use is
     * retrieved from the script file.
     */
    boolean runTransfer(SocketChannel sChannel, Selector selector,
        String protocol, long timeout, boolean isServer, boolean sendControlFlow) {
      System.out.println("runTransfer");
      if (sChannel == null) {
        start = System.currentTimeMillis();
        end = start;
        System.err.println("Socket not connected. Cannot run experiment.");
        return false;
      }

      if (protocolScript.isEmpty()) { // Should not happen
        log(System.out, "could not find any script, attempting to read");
        String[] proto_t = new String[1];
        if (readInScript(scriptFile, proto_t).length > 0)
          return false;
      }

      // No protocols found in script file!
      // (readInScript() already outputs error)
      if (protocolScript.isEmpty() || !protocolScript.containsKey(protocol))
        return false;

      GlasnostScript thisScript = protocolScript.get(protocol);

      long now = System.currentTimeMillis();
      start = now;

      long endTime = now + timeout; // expected end of transfer
      long lastPacket = now;
      long pause = 0;

      ByteBuffer message_payload = ByteBuffer.allocate(bufSizeBytes);
      ByteBuffer last_received_message = ByteBuffer.allocate(bufSizeBytes);

      bytesTransmitted = 0;
      bytesReceived = 0;
      lastState = -1;
      boolean startMeasuring = false;
      boolean protocolError = false;

      String linebuf = null;
      boolean found = false;
      int lineno = 1;

      int next_command_index = 0;

      while (next_command_index < thisScript.commands.size()) {

        GlasnostCommand curr_com = thisScript.commands.get(next_command_index);
        log(System.out, "executing command " + Integer.toString(next_command_index) + " of " + thisScript.commands.size() + " " + curr_com);

        if (curr_com.type == GlasnostCommand.CommandType.SEND) {

          boolean weSend = false;
          SendCommand send_com = (SendCommand) curr_com;
          if (send_com.endpoint == GlasnostCommand.EndPoint.CLIENT)
            weSend = !isServer;
          else
            weSend = isServer;

          if (weSend && sendControlFlow) {
            log(System.out,"send a:"+weSend);

            byte[] b = new byte[send_com.length];
            rnd.nextBytes(b);
            message_payload.clear();
            message_payload.put(b);
            message_payload.flip();

          } else if (weSend) {
            log(System.out,"send b:"+weSend);
            // Question: why do we create a message even when we do not have to
            // send? (i.e. weSend=false)
            createMessage(message_payload, send_com.payload,
                last_received_message);
          }

          now = System.currentTimeMillis();
          if (now >= endTime) {
            log(System.out, "Time is up, ending");
            break;
          }

          // Honor spacing between packets while sending
          if (pause > 0) {

            // Or add spacing to timing of last sent packet?
            pause -= (now - lastPacket);

            if (pause > 0) {
              try {
                sleep(pause);
              } catch (InterruptedException ie) {
                ie.printStackTrace();
              }
            }
            pause = 0;
          }

          if (startMeasuring) {
            start = System.currentTimeMillis();
            bytesTransmitted = 0;
            bytesReceived = 0;
            startMeasuring = false;
          }

          if (weSend) {

            int toSend = message_payload.remaining();
            // log(System.out, "Sending " + toSend + " bytes");

            // DEBUG
            // try {
            // byte[] tempb = new byte[toSend];
            // message_payload.get(tempb);
            // message_payload.rewind();
            // log(System.out, "SENDING:\n" + (new String(tempb, "US-ASCII")));
            // for (int i =0; i < tempb.length; ++i)
            // System.out.print(tempb[i] + " ");
            // System.out.println();
            // } catch (Exception e) {
            // }

            int w = writePacket(sChannel, selector, message_payload, endTime);

            if (w < 0) { // Error
              log(System.out, "writePacket failed");
              break;
            } else if ((w >= 0) && (w < toSend)) { // Timeout or socket closed
                                                   // in the middle
              bytesTransmitted += w;
              log(System.out, "writePacket did not write all bytes (" + w + "/"
                  + toSend + ")");
              break;
            }

            // System.out.println("DEBUG: ==write " + w + '/' + obuf.limit());

            lastPacket = System.currentTimeMillis();
            bytesTransmitted += w;
            message_payload.flip(); // Reset internal pointers

            last_received_message.clear();
            last_received_message.put(message_payload); // always holds the
                                                        // previous packet

            lastState = next_command_index;

          } else {

            log(System.out, "waitForRead("+send_com.length+")");
            // log(System.out, "Receiving " + send_com.length + " bytes");
            last_received_message.clear();
            assert (send_com.length <= last_received_message.capacity());
            last_received_message.limit(send_com.length);

            int r = readPacket(sChannel, selector, last_received_message,
                endTime);
            last_received_message.flip();

            // try {
            // /DEBUG
            // byte[] tempb = new byte[last_received_message.remaining()];
            // last_received_message.get(tempb);
            // last_received_message.rewind();
            // log(System.out, "RECEIVED:\n" + (new String(tempb, "US-ASCII")));
            // } catch (Exception e) {
            // }

            if (r < 0) { // Error
              log(System.out, "readPacket failed");
              break;
            } else if ((r >= 0) && (r < send_com.length)) { // Timeout or socket
                                                            // closed in the
                                                            // middle
              bytesReceived += r;
              log(System.out, "readPacket did not read all bytes (" + r + "/"
                  + send_com.length + ")");
              break;
            }
            log(System.out, "doneRead("+r+")");

            // System.out.println("DEBUG: ==read " + r + '/' + obuf.limit());

            // PROBLEM: Some packets have random content we can not check
            // against
            // if(!hasRandomData && !ibuf.equals(obuf)){
            // error(stream, "Packet received does not match expected packet.");
            // protocolError = true;
            // break;
            // }

            lastPacket = System.currentTimeMillis();
            bytesReceived += r;

            lastState = next_command_index;
          }

          next_command_index++;

        } else if (curr_com.type == GlasnostCommand.CommandType.PAUSE) {

          PauseCommand pause_com = (PauseCommand) curr_com;

          boolean weSend = false;
          if (pause_com.endpoint == GlasnostCommand.EndPoint.SERVER)
            weSend = isServer;
          else
            weSend = !isServer;

          if (weSend) {

            pause = (((int) (pause_com.sec)) * 1000)
                + (((int) (pause_com.usec)) / 1000);
            // log(System.out, "Pausing for " + pause + " milliseconds");
          }

          next_command_index++;

        } else if (curr_com.type == GlasnostCommand.CommandType.START_MEASURING) {

          // log(System.out, "Start measuring");
          startMeasuring = true;
          next_command_index++;

        } else if (curr_com.type == GlasnostCommand.CommandType.GOTO) {

          GotoCommand goto_com = (GotoCommand) curr_com;
          // log(System.out, "Goto command: jumping to command " +
          // goto_com.target_command);
          next_command_index = goto_com.target_command;
        }

        now = System.currentTimeMillis();
        if (now >= endTime) {
          log(System.out, "Time is up, ending");
          break;
        }

      }

      lastState = next_command_index;
      end = System.currentTimeMillis();

      log(System.out, "End of transfer; " + bytesTransmitted
          + " bytes transferred and " + bytesReceived + " bytes received");

      return (!protocolError && ((bytesTransmitted + bytesReceived) > 0));
    }

    /**
     * Read the next command from the (control) server.
     * 
     * Command is terminated by a newline (\n)
     * 
     * @param commandChannel
     * @param command
     * @return
     * @throws SocketTimeoutException
     * @throws IOException
     */
    public String readNextCommand(SocketChannel commandChannel,
        ByteBuffer command) throws SocketTimeoutException, IOException {

      byte[] buffer = null; // hold the line
      boolean commandFound = false;
      while (!commandFound) {
        byte[] cbuff = command.array();
        for (int i = 0; (i < command.position()) && (!commandFound); i++) {
          if (cbuff[i] == '\n') {
            buffer = new byte[i + 1];
            for (int n = 0; n <= i; n++)
              buffer[n] = cbuff[n];
            buffer[i] = 0;

            for (int n = i + 1; n < command.position(); n++)
              cbuff[n - (i + 1)] = cbuff[n];

            command.position(command.position() - (i + 1));
            commandFound = true;
          }
        }

        if (!commandFound) {
          int ret = commandChannel.read(command);

          if (ret < 0) {
            // System.err.println("Cannot read from command socket");
            String id = null;
            if (gr != null) {
              id = gr.testid;
            }
            handleFatalError("Server closed connection prematurely", "id=" + id
                + "&msg=Server%20connection%20closed%20prematurely&", 32);
            return null;
          }
        }
      }

      if (buffer == null)
        return null;

      String ret = new String(buffer, "US-ASCII");
      System.out.println("readNextCommand():" + ret);
      return ret;
    }

    /**
     * Initial communication with the measurement server to set up the test
     * environment, including what protocols should be used in the test.
     * 
     * @param commandChannel
     * @param inCommand
     *          , outCommand
     * 
     * @return false if an error occurred, true otherwise
     */
    boolean initialCommunicationAndSetup(SocketChannel commandChannel,
        ByteBuffer inCommand, ByteBuffer outCommand) {
      String commandStr = null;

      // First, check whether the server is ready to run a test
      try {
        String nextCommand = readNextCommand(commandChannel, inCommand);

        if (nextCommand == null)
          return false;
        if (nextCommand.startsWith("ip ") && (myIP == null)) {
          String[] parts = nextCommand.split(" ");
          assert (parts.length >= 2);
          myIP = parts[1];
          System.out.println("Server told me that my external IP is " + myIP);

          if (parts.length >= 3)
            myHostname = parts[2];

          if ((parts.length >= 5) && (parts[3].equals("id"))) {
            if (gr != null)
              gr.testid = parts[4];

            System.out.println("Test ID is " + parts[4]);
          }
        } else if (nextCommand.startsWith("busy ")) {
          String[] parts = nextCommand.split(" ");
          myIP = parts[1];

          String id = null;
          if (gr != null) {
            id = gr.testid;
          }
          handleFatalError("Server busy", "id=" + id
              + "&msg=Server%20busy&busy=1&", 1);
          return false;
        } else {
          System.err.println("Unknown response from server:" + nextCommand
              + ".");
        }
      } catch (SocketTimeoutException e) {
        // System.err.println("Server did not respond to our command. Aborting.");
        String id = null;
        if (gr != null) {
          id = gr.testid;
        }
        handleFatalError("Server timeout", "id=" + id
            + "&msg=Server%20not%20responding&mid=11", 33, e);
        return false;
      } catch (IOException e) {
        // System.err.println("Cannot read from command socket.");
        String id = null;
        if (gr != null) {
          id = gr.testid;
        }
        handleFatalError("Server connection IO failed", "id=" + id
            + "&msg=Server%20connection%20failed&mid=11", 34, e);
        return false;
      }

      // If the script file is located remotely, advice the server to load it
      if (scriptFile.startsWith("http") || scriptFile.startsWith("https")) {
        commandStr = "script " + scriptFile + '\n';
        try {
          outCommand.put(commandStr.getBytes("US-ASCII"));
        } catch (UnsupportedEncodingException e2) {
          System.exit(99);
        }
        outCommand.flip();
        try {
          System.out.print("Sending command: " + commandStr);
          commandChannel.write(outCommand);
        } catch (IOException e2) {
          System.out.println("Cannot send command to server.");
          String id = null;
          if (gr != null) {
            id = gr.testid;
          }
          handleFatalError("Server failed", "id=" + id
              + "&msg=Server%20failed&mid=11", 31, e2);
          return false;
        }
        outCommand.clear();

        try {
          String nextCommand = readNextCommand(commandChannel, inCommand);

          if (nextCommand == null)
            return false;

          if (nextCommand.startsWith("ok")) {
            System.out.println("Server has script file.");
          } else if (nextCommand.startsWith("no script")) {
            System.err
                .println("FATAL: Server was not able to retrieve script file "
                    + scriptFile);

            String id = null;
            if (gr != null) {
              id = gr.testid;
            }
            handleFatalError("Unknown script file", "id=" + id
                + "&msg=Unknown%20protocol&error=1&&unknown_protos="
                + nextCommand + '&', 1);
            return false;
          } else {
            System.err.println("Unknown response from server:" + nextCommand
                + ".");
          }
        } catch (SocketTimeoutException e) {
          // System.err.println("Server did not respond to our command. Aborting.");
          String id = null;
          if (gr != null) {
            id = gr.testid;
          }
          handleFatalError("Server timeout", "id=" + id
              + "&msg=Server%20not%20responding&mid=11", 33, e);
          return false;
        } catch (IOException e) {
          // System.err.println("Cannot read from command socket.");
          String id = null;
          if (gr != null) {
            id = gr.testid;
          }
          handleFatalError("Server connection IO failed", "id=" + id
              + "&msg=Server%20connection%20failed&mid=11", 34, e);
          return false;
        }
      }

      // Check whether the servers knows all the protocols I want to run
      assert (protocol.length > 0);
      commandStr = "protos " + protocol[0];
      for (int i = 1; i < protocol.length; i++) {
        if (!protocol[i].equals("none"))
          commandStr += ';' + protocol[i];
      }
      commandStr += '\n';

      try {
        outCommand.put(commandStr.getBytes("US-ASCII"));
      } catch (UnsupportedEncodingException e2) {
        System.exit(99);
      }
      outCommand.flip();
      try {
        System.out.print("Sending command: " + commandStr);
        commandChannel.write(outCommand);
      } catch (IOException e2) {
        // System.err.println("Cannot send command to server.");
        String id = null;
        if (gr != null) {
          id = gr.testid;
        }
        handleFatalError("Server failed", "id=" + id
            + "&msg=Server%20failed&mid=11", 31, e2);
        return false;
      }
      outCommand.clear();

      try {
        String nextCommand = readNextCommand(commandChannel, inCommand);

        if (nextCommand == null)
          return false;

        if (nextCommand.startsWith("ok")) {
          System.out
              .println("Server knows all the protocols I want to replay!");
        } else if (nextCommand.startsWith("no proto ")) {
          String id = null;
          if (gr != null) {
            id = gr.testid;
          }
          handleFatalError("Unknown protocol", "id=" + id
              + "&msg=No%20protocol&error=1&", 1);
          return false;
        } else if (nextCommand.startsWith("unknown proto ")) {
          nextCommand = nextCommand.substring(14, nextCommand.length() - 1);

          System.err.println("FATAL: Server does not know protocol(s) "
              + nextCommand);

          String id = null;
          if (gr != null) {
            id = gr.testid;
          }
          handleFatalError("Unknown protocol", "id=" + id
              + "&msg=Unknown%20protocol&error=1&unknown_protos=" + nextCommand
              + '&', 1);
          return false;
        } else {
          System.err.println("Unknown response from server:" + nextCommand
              + ".");
        }
      } catch (SocketTimeoutException e) {
        // System.err.println("Server did not respond to our command. Aborting.");
        String id = null;
        if (gr != null) {
          id = gr.testid;
        }
        handleFatalError("Server timeout", "id=" + id
            + "&msg=Server%20not%20responding&mid=11", 33, e);
        return false;
      } catch (IOException e) {
        // System.err.println("Cannot read from command socket.");
        String id = null;
        if (gr != null) {
          id = gr.testid;
        }
        handleFatalError("Server connection IO failed", "id=" + id
            + "&msg=Server%20connection%20failed&mid=11", 34, e);
        return false;
      }

      return true;
    }

    public void run() {

      int soTimeout = 10000; // 10 seconds

      Selector selector = null;
      SocketChannel sChannel = null;
      SelectionKey selKey = null;

      String commandStr = null;

      /*
       * Java on MacOS X prevents applets from opening a selector due to some
       * property reading that's not allowed. Thus, the applet must be signed
       * and the code below allows us to escape the sandbox.
       * 
       * NOTE: The Makefile automatically builds JARs with and without this
       * code. It uses the MACONLY markers to uncomment the code, so please do
       * not remove these markers.
       */

      /*
       * MACONLY if(gr != null){ selector = (Selector)
       * AccessController.doPrivileged(new PrivilegedAction() { public Object
       * run() { Selector selector = null; try { selector = Selector.open(); }
       * catch (IOException e1) { System.err.println("Creating selector failed."
       * + e1); e1.printStackTrace(); String id = null; if(gr != null){ id =
       * gr.testid; } handleFatalError("Internal error", "id=" + id +
       * "&msg=selector%20failed", 4); return null; }
       * 
       * return selector; } }); if(selector == null) return; } else{ MACONLY
       */
      try {
        selector = Selector.open();
      } catch (IOException e1) {
        System.err.println("Creating selector failed." + e1);
        e1.printStackTrace();
        String id = null;
        if (gr != null) {
          id = gr.testid;
        }
        handleFatalError("Internal error", "id=" + id
            + "&msg=selector%20failed", 4);
        return;
      }
      /*
       * MACONLY } MACONLY
       */

      // Open a TCP connection to the server
      SocketChannel commandChannel = null;
      ByteBuffer inCommand = ByteBuffer.allocate(32000);
      ByteBuffer outCommand = ByteBuffer.allocate(32000);
      try {
        log(System.out, "Connecting to commandChannel:"+serverIP+":"+commandPort);
        commandChannel = SocketChannel.open(new InetSocketAddress(serverIP,
            commandPort));
        commandChannel.configureBlocking(true);
        commandChannel.socket().setSoTimeout(soTimeout);
      } catch (IOException e) {
        System.err.println("Cannot connect to server.");
        String id = null;
        if (gr != null) {
          id = gr.testid;
        }
        handleFatalError("Cannot connect to server", "id=" + id
            + "&msg=Cannot%20connect%20to%20server&mid=10", 8, e);
        return;
      }

      // Set up environment for test runs with measurement server
      if (!initialCommunicationAndSetup(commandChannel, inCommand, outCommand))
        return;

      String results = "";
      int exp = 0;

      while (!isTerminated
          && ((upstream[0] + upstream[1] + downstream[0] + downstream[1]) > 0)) {

        // Command string:
        // "replay <Protocol> <server/client> <duration> port <port> .\n"
        String proto = null;
        GlasnostScript gscript = null;
        boolean isServer = false;
        boolean sendControlFlow = false;
        long timeout;

        // This will first execute all upstream experiments and then downstream
        // experiments
        if ((upstream[0] > 0) && (upstream[0] >= upstream[1])) {
          proto = protocol[0];
          gscript = protocolScript.get(proto);
          isServer = true;

          timeout = duration;
          if ((timeout <= 0) && gscript.duration > 0) { // duration = 0 equals
                                                        // to unsepecified
            timeout = gscript.duration;
            System.out.println("Setting test duration to " + timeout
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
          gscript = protocolScript.get(proto);
          isServer = true;
          timeout = duration;
          if ((timeout <= 0) && gscript.duration > 0) {
            timeout = gscript.duration;
            System.out.println("Setting test duration to " + timeout
                + " as set by the test script.");
          }

          if (timeout <= 0)
            timeout = DefaultDuration;
        } else if ((downstream[0] > 0) && (downstream[0] >= downstream[1])) {
          proto = protocol[0];
          gscript = protocolScript.get(proto);
          isServer = false;

          timeout = duration;
          if ((timeout <= 0) && gscript.duration > 0) {
            timeout = gscript.duration;
            System.out.println("Setting test duration to " + timeout
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
          gscript = protocolScript.get(proto);

          timeout = duration;
          if ((timeout <= 0) && gscript.duration > 0) {
            timeout = gscript.duration;
            System.out.println("Setting test duration to " + timeout
                + " as set by the test script.");
          }

          if (timeout <= 0)
            timeout = DefaultDuration;
          timeout += 1000;
        } else {
          break;
        }
        assert (proto != null);

        if (timeout > MaximumDuration) {
          timeout = MaximumDuration;
          System.out.println("Restricting test duration to " + timeout
              + " which is the maximum configured in Glasnost.");
        }

        int port;
        if ((serverPort[1] > -3) && (upstream[0] <= 0) && (upstream[1] <= 0)
            && (downstream[0] <= numberOfRepeats)
            && (downstream[1] <= numberOfRepeats)) {
          port = serverPort[1];
          // if((port <= 0) && protocolPort.containsKey(proto) &&
          // (protocolPort.get(proto).length > 1)){
          if ((port <= 0) && gscript.port.length > 1) {
            port = gscript.port[1];
            System.out.println("Setting port to " + port
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
            System.out.println("Setting port to " + port
                + " as set by the test script.");
            serverPort[1] = port;
            // if(gr != null)
            // gr.mPort[1] = serverPort[1];
          }
        } else {
          port = serverPort[0];
          if ((port <= 0) && gscript.port.length > 0) {
            port = gscript.port[0];
            System.out.println("Setting port to " + port
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
          // System.err.println("FATAL: Do not know what experiment to run next. Aborting.");
          String id = null;
          if (gr != null) {
            id = gr.testid;
          }
          handleFatalError("Setup failed", "id=" + id + "&msg=No%20command", 30);
          return;
        }
        try {
          outCommand.put(commandStr.getBytes("US-ASCII"));
        } catch (UnsupportedEncodingException e2) {
          System.exit(99);
        }
        outCommand.flip();
        try {
          System.out.print("Sending command: " + commandStr);
          commandChannel.write(outCommand);
        } catch (IOException e2) {
          // System.err.println("Cannot send command to server.");
          String id = null;
          if (gr != null) {
            id = gr.testid;
          }
          handleFatalError("Server failed", "id=" + id
              + "&msg=Server%20failed&mid=11", 31, e2);
          return;
        }
        outCommand.clear();

        try {
          String nextCommand = readNextCommand(commandChannel, inCommand);

          if (nextCommand == null) {
            System.err.println("No response from server.");
            return;
          } else if (nextCommand.startsWith("ok")) {
            System.out.println("Server responded with OK.");
          } else if (nextCommand.startsWith("port ")) {
            String[] parts = nextCommand.split(" ");

            // Change standard port to the one we got from the server
            if (commandStr.contains("port " + String.valueOf(serverPort[0]))) {
              serverPort[0] = Integer.valueOf(parts[1]);
              // if(gr != null)
              // gr.mPort[0] = serverPort[0];
            } else if ((serverPort[1] > -3)
                && commandStr.contains("port " + String.valueOf(serverPort[1]))) {
              serverPort[1] = Integer.valueOf(parts[1]);
              // if(gr != null)
              // gr.mPort[1] = serverPort[1];
            }

            System.out.println("Server changed port to " + parts[1] + ".");
            port = Integer.valueOf(parts[1]);
          } else if (nextCommand.startsWith("busy ")) {
            String[] parts = nextCommand.split(" ");
            myIP = parts[1];

            String id = null;
            if (gr != null) {
              id = gr.testid;
            }
            handleFatalError("Server busy", "id=" + id
                + "&msg=Server%20busy&busy=1&", 1);
            return;
          } else {
            System.err.println("Unknown response from server:" + nextCommand
                + ".");
            continue;
          }
        } catch (SocketTimeoutException e) {
          // System.err.println("Server did not respond to our command. Aborting.");
          String id = null;
          if (gr != null) {
            id = gr.testid;
          }
          handleFatalError("Server timeout", "id=" + id
              + "&msg=Server%20not%20responding&mid=11", 33, e);
          return;
        } catch (IOException e) {
          // System.err.println("Cannot read from command socket.");
          String id = null;
          if (gr != null) {
            id = gr.testid;
          }
          handleFatalError("Server connection IO failed", "id=" + id
              + "&msg=Server%20connection%20failed&mid=11", 34, e);
          return;
        }

        // Now connecting to the server for test run
        sChannel = setupSocket(new InetSocketAddress(serverIP, port), selector,
            soTimeout);

        selKey = null;
        if (sChannel != null) {
          try {
            selKey = sChannel.register(selector, SelectionKey.OP_WRITE
                | SelectionKey.OP_READ);
          } catch (ClosedChannelException e1) {
            System.err.println("Cannot register socket with select: " + e1);
            e1.printStackTrace();
            String id = null;
            if (gr != null) {
              id = gr.testid;
            }
            handleFatalError("Internal error", "id=" + id
                + "&msg=register%20failed", 8, e1);
            return;
          }
        }

        // Reset
        lastState = -1;
        bytesTransmitted = 0;
        bytesReceived = 0;
        end = 0;

        System.out.println("Running "
            + (sendControlFlow ? "control flow for " : "") + proto + " as "
            + (isServer ? "server" : "client") + " on port " + port + '.');
        if (cd != null)
          cd.addToBound((int) (timeout / 1000.0));
        start = System.currentTimeMillis();
        boolean transferSuccessful = runTransfer(sChannel, selector, proto,
            timeout, isServer, sendControlFlow);
        if (end == 0)
          end = System.currentTimeMillis();

        double timespan = (end - start) / 1000.0;
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
          System.out.println("FAILED: " + proto + " transfer reset.");
          backLog += "Transfer reset in state " + lastState + " .\n";
        } else if (!transferSuccessful) {
          System.out.println("FAILED: " + proto + " transfer as "
              + (isServer ? "server" : "client") + " failed.");
        }
        System.out.println("Transferred " + bytesTransmitted
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

        if (backLog.length() > 0) {
          String part[] = backLog.split("\n");

          try {
            for (int i = 0; i < part.length; i++) {
              if (part[i].length() == 0)
                continue;

              outCommand.put("log ".getBytes("US-ASCII"));
              outCommand.put(part[i].getBytes("US-ASCII"));
              outCommand.put("\n".getBytes("US-ASCII"));
            }
          } catch (UnsupportedEncodingException e2) {
            System.exit(99);
          }
          outCommand.flip();
          try {
            // System.out.print("Sending log: " + backLog);
            commandChannel.write(outCommand);
          } catch (IOException e2) {
            // System.err.println("Cannot send log to server.");
            String id = null;
            if (gr != null) {
              id = gr.testid;
            }
            handleFatalError("Server failed", "id=" + id
                + "&msg=Server%20failed&mid=11", 31, e2);
            return;
          }
          outCommand.clear();
          backLog = "";
        }

        // Clean up
        try {
          selKey.cancel();
          if (sChannel.isConnected()) {
            sChannel.configureBlocking(false);
            sChannel.close();
            // sChannel.configureBlocking(true);
            // sChannel.socket().close();
          }
        } catch (IOException e) {
          // System.err.println("Cannot close socket. " + e);
          String id = null;
          if (gr != null) {
            id = gr.testid;
          }
          handleFatalError("Socket failure", "id=" + id
              + "&msg=Cannot%20close%20socket&mid=11", 36, e);
          return;
        }

        // Sleep X seconds and give the server some time to prepare for the next
        // round and to drain queues
        try {
          sleep(Pause);
        } catch (InterruptedException e) {
        }
      }

      try {
        selector.close();
      } catch (IOException e) {
        System.err.println("Cannot close selector.");
      }

      // Transmit over command socket what to do next and wait for answer
      commandStr = "shutdown \n";
      try {
        outCommand.put("log Sysinfo: ".getBytes("US-ASCII"));
        outCommand.put(sysinfo.getBytes("US-ASCII"));
        outCommand.put("\n".getBytes("US-ASCII"));

        outCommand.put("log http ".getBytes("US-ASCII"));
        outCommand.put(results.getBytes("US-ASCII"));
        String extra = "peer=" + myIP + "&hostname=" + myHostname
            + "&done=yes&";
        if (specInJar)
          extra += "internal=1&";
        if (gr != null)
          extra += "id=" + gr.testid + "&server=" + gr.mServer + "&port="
              + gr.mPort[0] + "&port2=" + gr.mPort[1] + '&' + gr.expParam;
        outCommand.put(extra.getBytes("US-ASCII"));
        outCommand.put("\n".getBytes("US-ASCII"));

        outCommand.put(commandStr.getBytes("US-ASCII"));
      } catch (UnsupportedEncodingException e2) {
        System.exit(99);
      }
      outCommand.flip();
      try {
        commandChannel.write(outCommand);
        outCommand.clear();
      } catch (IOException e2) {
        System.err.println("Cannot send command to server.");
        // return; // Let's ignore this problem for the moment
      }

      // Wait for a final OK, giving the server time to finish its business
      // The server also sends aggregated results here
      String serverResults = "";
      try {
        /*
         * boolean connectionTerminated = false; while(!connectionTerminated){
         * int ret = commandChannel.read(inCommand);
         * 
         * if (ret < 0) {
         * //System.err.println("Cannot read from command socket");
         * connectionTerminated = true; break; }
         * 
         * String[] part = (new String(inCommand.array(), 0,
         * inCommand.position())).split("\n"); for(int i=0; i<part.length; i++){
         * if(part[i].equals("ok")){ // OK on its own line terminates the
         * connection connectionTerminated = true;
         * System.out.println("Server responded with OK."); break; } } }
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

        while (true) {
          String nextCommand = readNextCommand(commandChannel, inCommand);

          if (nextCommand.startsWith("ok"))
            break;

          if (nextCommand.startsWith("log "))
            serverResults += nextCommand.substring(4);
          else
            serverResults += "unknown=" + nextCommand + '&';
        }
      } catch (Exception e) {
      } // Ignore at this point

      // We are done, send back results to webserver
      if (gr != null) {
        gr.displayResultPage("peer=" + myIP + "&hostname=" + myHostname + '&'
            + results + '&' + serverResults);
        gr.finished = true;
        gr.rpw = null;
      } else {
        System.out.println("peer=" + myIP + "&hostname=" + myHostname + '&'
            + results + '&' + serverResults);
      }

    }

    private void handleFatalError(String message, String errorParams,
        int errorCode) {
      this.handleFatalError(message, errorParams, errorCode, null);
    }

    private void handleFatalError(String message, String errorParams,
        int errorCode, Exception e) {

      isTerminated = true;

      if ((gr != null) && (errorParams != null)) {

        if (gr.rpw != null)
          gr.rpw.isTerminated = true;
        gr.printItem(message);

        URL nextPage;
        try {
          // Encode text
          String[] part;
          if (!sysinfo.equals("")) {
            part = sysinfo.split(" ");
            sysinfo = "sysinfo=" + part[0];
            for (int i = 1; i < part.length; i++) {
              sysinfo += "%20" + part[i];
            }
          }
          String exception = "";
          if (e != null) {
            String eMsg = e.getMessage();
            if ((eMsg != null) && !eMsg.equals("")) {
              part = eMsg.split(" ");
              exception = "exception=" + part[0];
              for (int i = 1; i < part.length; i++) {
                exception += "%20" + part[i];
              }
            }
          }

          String nextPageStr = null;
          if (gr.nextPage.endsWith("&"))
            nextPageStr = "http://" + gr.nextPage + "error=1&" + errorParams
                + "&peer=" + myIP + '&' + exception + '&' + sysinfo
                + "&server=" + gr.mServer + "&port=" + gr.mPort[0] + "&port2="
                + gr.mPort[1] + '&' + gr.expParam;
          else
            nextPageStr = "http://" + gr.nextPage + "?error=1&" + errorParams
                + "&peer=" + myIP + '&' + exception + '&' + sysinfo
                + "&server=" + gr.mServer + "&port=" + gr.mPort[0] + "&port2="
                + gr.mPort[1] + '&' + gr.expParam;

          try {
            nextPage = new URL(nextPageStr);
            gr.displayResultPage(nextPage); // Go to a special error handling
                                            // webpage
          } catch (MalformedURLException me) {
            System.err.println("URL '" + nextPageStr + "' malformed: " + me);
            e.printStackTrace();
          }
        } catch (Exception me) {
          me.printStackTrace();
        }
      } else {
        System.err.println("Error: " + message);
        if (e != null) {
          System.err.println("Exception: " + e.getMessage());
          e.printStackTrace();
        }
        if (!sysinfo.equals("")) {
          System.err.println("Sysinfo: " + sysinfo);
        }
        System.exit(errorCode);
      }
    }
  }

  /** Initializes the applet */

  public void init() {

    System.out.println("Starting Glasnost Replayer version " + VERSION);

    buffer = new StringBuffer();

    String str = getParameter("down");
    if (str != null)
      this.down = Boolean.valueOf(str);
    str = getParameter("up");
    if (str != null)
      this.up = Boolean.valueOf(str);

    str = getParameter("repeat");
    if (str != null)
      this.repeat = Integer.valueOf(str);
    str = getParameter("duration");
    if (str != null)
      this.duration = Integer.valueOf(str);

    mProtocol[0] = getParameter("protocol1");
    mProtocol[1] = getParameter("protocol2");

    if (mProtocol[0] == null) {
      System.err
          .println("Misconfiguration: You have to specify the protocols to use!");
      return;
    }
    if (mProtocol[1] == null) {
      System.err
          .println("No second protocol specified, will send control flow instead.");
      String p = mProtocol[0];
      mProtocol = new String[1];
      mProtocol[0] = p;
    }

    if (!up && !down) {
      System.err
          .println("Misconfiguration: Choose either or both up and down traffic!");
      return;
    }

    str = getParameter("nextPage"); // The next page to call
    if (str != null)
      nextPage = str;

    // The planet just can be the server we got this applet from
    mServer = getCodeBase().getHost();
    // If the applet was loaded from another server than the one that served the
    // webpage,
    // the code above will still return the name of the webpage-server.
    str = getParameter("server");
    if (str != null)
      mServer = str;

    str = getParameter("scriptFile");
    if (str != null)
      mScriptFile = "http://" + mServer
          + ":19981/?retrieve=script&recursive=1&id=" + str;

    // Ports with 0, -1, and -2 let the server select
    // Port is by default 0, port2 is by default disabled (only test on single
    // port)
    String port = getParameter("port");
    if ((port != null)
        && ((Integer.valueOf(port) >= 0) || (Integer.valueOf(port) == -1)))
      mPort[0] = Integer.valueOf(port);
    else
      mPort[0] = 0;
    String port2 = getParameter("port2");
    if ((port2 != null)
        && ((Integer.valueOf(port2) >= 0) || (Integer.valueOf(port2) == -2)))
      mPort[1] = Integer.valueOf(port2);
    else
      mPort[1] = -3;

    // Temporary. The server gives us the real testid during the transfer.
    this.testid = String.valueOf((int) (System.currentTimeMillis() / 1000.0));
    if (getParameter("ID") != null)
      this.testid = getParameter("ID");

    // Remember all parameters that drive this experiment
    if (mProtocol.length == 2)
      expParam = "protocol1=" + mProtocol[0] + "&protocol2=" + mProtocol[1]
          + "&down=" + this.down + "&up=" + this.up + "&repeat=" + this.repeat
          + "&duration=" + this.duration + "&";
    else
      expParam = "protocol1=" + mProtocol[0] + "&down=" + this.down + "&up="
          + this.up + "&repeat=" + this.repeat + "&duration=" + this.duration
          + "&";

    str = getParameter("browserWorkaround");
    if (str != null)
      browserWorkaround = Boolean.parseBoolean(str);

    setBackground(Color.WHITE);
  }

  public void start() {
    printItem("Starting measurement...");

    sysinfo = System.getProperty("os.name") + ','
        + System.getProperty("os.arch") + ','
        + System.getProperty("os.version") + ','
        + System.getProperty("java.vendor") + ','
        + System.getProperty("java.version");

    // Only run one instance of the Worker thread!
    if (rpw == null) {
      appletContext = getAppletContext();

      try {
        // This simetimes does not work for some Java plugins (e.g., IcedTea)
        appletContext.showDocument(new URL("javascript:disablePhpTimeout()"));
      } catch (MalformedURLException e) {
      }

      try {
        rpw = new ReplayWorker(mServer, mScriptFile, mProtocol, mPort, this);
      } catch (Exception e) {
        System.err.println("Fatal: Constructor ReplayWorker failed.");
        printItem("Fatal internal error.");
        return;
      }

      rpw.initalSetup(up, down, repeat, duration);

      String str = getParameter("myIP");
      if (str != null)
        rpw.myIP = str;

      rpw.start();
    }

    printItem("Test is running...");
  }

  public void stop() {
    // printItem("Stopping applet");
    // rpw.isTerminated = true; // ??? Is this called whenever the applet looses
    // the focus?
  }

  public void destroy() {

    if (rpw != null) {
      rpw.isTerminated = true;
      rpw = null;
    }
  }

  public void displayResultPage(String results) {

    /* Finally, open the web page that shows the results */
    String nextURL = null;

    if (nextPage.startsWith("http://"))
      nextURL = "";
    else
      nextURL = "http://";

    if (nextPage.endsWith("&"))
      nextURL += nextPage + "id=" + testid + "&done=yes&server=" + mServer
          + "&port=" + mPort[0] + "&port2=" + mPort[1] + '&' + expParam;
    else
      nextURL += nextPage + "?id=" + testid + "&done=yes&server=" + mServer
          + "&port=" + mPort[0] + "&port2=" + mPort[1] + '&' + expParam;

    if (rpw.specInJar)
      nextURL += "internal=1&";

    nextURL += results;

    // Internet Explorer only supports URLs up to 2,048 characters (GET). To
    // work-around this
    // limitation, we detour through a proxy that transforms the results into a
    // HTTP-POST request
    if (browserWorkaround && (nextURL.length() > 2040)) {
      if (nextPage.startsWith("http://"))
        nextURL = "http://" + mServer + ":19981/?id=" + testid + "&ip="
            + rpw.myIP + "&hostname=" + rpw.myHostname + "&server=" + mServer
            + "&nextPage=" + nextPage;
      else
        nextURL = "http://" + mServer + ":19981/?id=" + testid + "&ip="
            + rpw.myIP + "&hostname=" + rpw.myHostname + "&server=" + mServer
            + "&nextPage=http://" + nextPage;
    }

    printItem("Opening results page...");
    URL url = null;
    try {
      url = new URL(nextURL);
    } catch (MalformedURLException e) {
      System.err.println("Malformed URL: " + nextURL);
    }

    if (url != null) {
      appletContext.showDocument(url);
    }
  }

  public void displayResultPage(URL url) {

    if (url != null) {
      printItem("Opening next page...");
      appletContext.showDocument(url);
    }
  }

  private void addItem(String newWord) {
    buffer.append(newWord);
    repaint();
  }

  private void printItem(String newWord) {
    buffer.delete(0, buffer.length());
    buffer.append(newWord);
    repaint();
  }

  /**
   * Plots to the applet frame text and does also a progress bar.
   */

  public void paint(Graphics g) {
    Dimension FrameDimension = getSize();
    int BarPixelWidth = (FrameDimension.width * done) / totalLength;

    // Fill the bar the appropriate percent full.
    g.setColor(Color.decode("0x69acff")); // MPI blue

    // Draw a Rectangle around the applet's display area.
    g.drawRect(0, 0, getWidth() - 1, getHeight() - 1);

    // Draw progress bar
    g.fillRect(0, 0, BarPixelWidth, FrameDimension.height);

    // Set the color of the text
    g.setColor(Color.black);

    // Calculate the width of the string in pixels. Used to center the string in
    // the progress bar window
    FontMetrics fm = g.getFontMetrics(g.getFont());
    int StringPixelWidth = fm.stringWidth(buffer.toString());

    g.drawString(buffer.toString(),
        (FrameDimension.width - StringPixelWidth) / 2, 24);
  }

  public String[][] getParameterInfo() {
    String[][] info = {
        // Parameter Name Kind of Value Description
        { "protocol1", "String", "Name of the first protocol to use" },
        { "protocol2", "String", "Name of the second protocol to use" },
        { "port", "Integer", "Port of the server to connect to (default: 6881)" },
        { "port2", "Integer", "Another port of the server to connect to" },
        { "down", "Boolean", "Whether to emulate downstream traffic" },
        { "up", "Boolean", "Whether to emulate upstream traffic" },
        { "repeat", "Integer",
            "How often a single experiment should be repeated" },
        { "duration", "Integer",
            "The timeout for a single test (in seconds, default: 5)" },
        {
            "scriptFile",
            "String",
            "File name or URL of a protocol description file (optional; default: internal file)" },
        { "server", "String", "Server this applet was loaded from" },
        { "nextPage", "String",
            "Full URL to next page to call after the applet finished" },
        { "browserWorkaround", "Boolean",
            "Should be set true for InternetExplorer" }, };
    return info;
  }

  public String getAppletInfo() {
    return "GlasnostReplayer "
        + VERSION
        + "\nRuns transfers to check for traffic differentiation.\nContact: Marcel Dischinger <mdischin@mpi-sws.org>\n";
  }

  /**
   * What parameter main() takes. Not giving a second application protocol will
   * cause GlasnostReplayer to use protocol1 but sending random bytes for the
   * payload. To only replay a single flow, specify the second protocol as
   * 'none'. protocolSpecFile can also be a URL
   */
  public static void usage() {
    System.err
        .println("Usage: GlasnostReplayer <serverIP> -a1 <ApplicationProtocol1> -p1 <port1> [-a2 <ApplicationProtocol2>] [-p2 <port2>]");
    System.err
        .println("                        [-up (true|false)] [-down (true|false)] [-r <repeats>] [-t <timeout>] [-o <outputFile>] [-s <protocolSpecFile>]");
    System.exit(1);
  }

  /**
   * @param args
   *          see usage()
   */
  public static void main(String[] args) {

    if (args.length < 7 || args.length > 21) {
      System.err.println("Error: Wrong number of parameters!");
      usage();
    }

    String[] protocol = new String[2];
    int[] port = new int[2];
    String scriptFile = "protocols.spec";

    boolean up = false, down = false;
    int repeat = 1;
    int duration = -1;
    String filename = null;

    for (int i = 1; i < args.length; i++) {

      if (args[i].equalsIgnoreCase("-a1")
          || args[i].equalsIgnoreCase("-proto1")) {
        i++;
        if (i >= args.length)
          usage();
        protocol[0] = args[i];
      } else if (args[i].equalsIgnoreCase("-a2")
          || args[i].equalsIgnoreCase("-proto2")) {
        i++;
        if (i >= args.length)
          usage();
        protocol[1] = args[i];
      } else if (args[i].equalsIgnoreCase("-p1")
          || args[i].equalsIgnoreCase("-port")
          || args[i].equalsIgnoreCase("-port1")) {
        i++;
        if (i >= args.length)
          usage();
        port[0] = Integer.valueOf(args[i]);

      } else if (args[i].equalsIgnoreCase("-p2")
          || args[i].equalsIgnoreCase("-port2")) {
        i++;
        if (i >= args.length)
          usage();
        port[1] = Integer.valueOf(args[i]);
      } else if (args[i].equalsIgnoreCase("-up")) {
        i++;
        if (i >= args.length)
          usage();
        up = Boolean.valueOf(args[i]);
      } else if (args[i].equalsIgnoreCase("-down")) {
        i++;
        if (i >= args.length)
          usage();
        down = Boolean.valueOf(args[i]);
      } else if (args[i].equalsIgnoreCase("-r")) {
        i++;
        if (i >= args.length)
          usage();
        repeat = Integer.valueOf(args[i]);
      } else if (args[i].equalsIgnoreCase("-t")) {
        i++;
        if (i >= args.length)
          usage();
        duration = Integer.valueOf(args[i]);
      } else if (args[i].equalsIgnoreCase("-o")) {
        i++;
        if (i >= args.length)
          usage();
        filename = args[i];
      } else if (args[i].equalsIgnoreCase("-s")) {
        i++;
        if (i >= args.length)
          usage();
        scriptFile = args[i];
      } else {
        System.err.println("Unknown option: " + args[i]);
        usage();
      }
    }

    if (protocol[0] == null) {
      System.err
          .println("You have to specify at least one protocol for replay!");
      usage();
    }

    if (port[0] <= 0) {
      System.err.println("You have to specify at least one port to use!");
      usage();
    }

    if (!up && !down) {
      System.err
          .println("You have to specify at least one of -up or -down with true.");
      usage();
    }
    if (repeat <= 0) {
      System.err.println("-r must be at least 1.");
      usage();
    }

    ReplayWorker rpw = null;

    try {
      if (protocol[1] == null) {
        String[] p = new String[1];
        p[0] = protocol[0];
        rpw = new ReplayWorker(args[0], scriptFile, false, p, port);
      } else
        rpw = new ReplayWorker(args[0], scriptFile, false, protocol, port);

    } catch (Exception e) {
      System.err.println("Fatal: Constructor ReplayWorker failed.");
      System.exit(1);
    }

    rpw.initalSetup(up, down, repeat, duration);
    rpw.setFileOutput(filename);

    rpw.start();
  }

}
