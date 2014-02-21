JAVAC=javac
CXX_FLAGS=-g -Wall

all: server

server: gserver

applet: GlasnostReplayer.jar
applet-mac: GlasnostReplayerMac.jar

%.o: %.cc
	@echo ==\> $<
	$(CXX) $(CXX_FLAGS) $< -c -o $@

%.o: %.c
	@echo ==\> $<
	$(CXX) $(CXX_FLAGS) $< -c -o $@

trace-daemon: trace-daemon.o tools.o 
	$(CXX) $^ -o trace-daemon -pthread -lmicrohttpd $(CXX_FLAGS)

glasnost_replayer: glasnost_replayer.o tools.o glasnost_parser.o
	$(CXX) -lpcap -lcurl -lz $(CXX_FLAGS) $^ -o $@

dump2script: dump2script.o tools.o
	$(CXX) -lpcap $(CXX_FLAGS) $^ -o $@

gserver: gserver.o glasnost_replayer.o http_server.o tools.o glasnost_parser.o
	$(CXX) -lpcap -lcurl -lz -lmicrohttpd $(CXX_FLAGS) $^ -o $@ 

http_server: http_server.o tools.o glasnost_parser.o
	$(CXX) $^ -o http_server -pthread -lcurl -lmicrohttpd $(CXX_FLAGS)

script_validator: script_validator.o glasnost_parser.o tools.o
	$(CXX) $(CXX_FLAGS) $^ -o $@

static: gserver.o glasnost_replayer.o http_server.o tools.o glasnost_parser.o
	$(CXX) $^ -pthread -lz -lrt curl/lib/libcurl.a /usr/lib/libpcap.a /usr/lib/libmicrohttpd.a $(CXX_FLAGS) -o gserver
	
protocols.spec.marshalled: script_validator
	#cat glasnost-tests/* > protocols.spec
	./script_validator protocols.spec

GlasnostReplayer.jar: GlasnostReplayer.java protocols.spec.marshalled
	$(JAVAC) GlasnostReplayer.java
	jar cfm GlasnostReplayer.jar GlasnostReplayer.manifest GlasnostReplayer*.class protocols.spec.marshalled

GlasnostReplayerMac.jar: GlasnostReplayer.java protocols.spec.marshalled
	mkdir -p build
	rm -f build/*.class
	cp protocols.spec.marshalled GlasnostReplayer.manifest build/
	cat GlasnostReplayer.java |grep -v MACONLY >build/GlasnostReplayer.java
	(cd build && $(JAVAC) GlasnostReplayer.java)
	(cd build && jar cfm GlasnostReplayerMac.jar GlasnostReplayer.manifest GlasnostReplayer*.class protocols.spec.marshalled)
	mv build/GlasnostReplayerMac.jar .
	rm -f build/*.class build/GlasnostReplayer.java build/protocols.spec.marshalled build/GlasnostReplayer.manifest
	rmdir build
	@echo "----------------------------------------------------------------------------------------------"
	@echo "You have to sign GlasnostReplayerMac.jar as it needs to execude a privileged function on Macs."
	@echo "We recommend to use the precompiled and signed jar we provide on"
	@echo " http://broadband.mpi-sws.org/transparency/contribute.html"
	@echo ""
	@echo "How to sign a java applet:"
	@echo "  (1) Generate a self-signed certificate if you do not already have one:"
	@echo "         keytool -genkey -alias yourAlias -validity 365"
	@echo "  (2) Sign the jar:"
	@echo "         jarsigner GlasnostReplayerMac.jar yourAlias"


clean::
	rm -fv *.class gserver script_validator *.o 

maintainer-clean:: clean
	rm -fv *.jar 
