# Glasnost Parser v2.
# Developed 2011/2012 by Hadi Asghari (http://deeppacket.info)
#
# Statistics about test streams

class GlasMeasurement:
    """" Class to hold statistics about one test stream """
    def __init__(self, direction, port_typ, flow_typ, tcp_port):
        assert direction in ['u','d']
        assert flow_typ  in ['af', 'cf'] # app-flow vs control-flow
        assert port_typ  in ['ap', 'np'] # app-port vs neutral-port
        self.proto 	    = flow_typ
        self.port	    = port_typ
        self.tcp_port   = int(tcp_port)
        self.dir 	    = direction


    ##########################################################

    @staticmethod
    def oldstyle1_factory(ts, old_prot, old_di, old_port):
        direction = "u" if old_di=="downstream" else "d" if old_di=="upstream" else None
                # NOTE: U/D REVERSED. the log files and the server files explain it differently.
                # with this flip here, the problem in speed() is solved
        port_type = 'ap' if 6889 >=old_port>= 6881 else 'np'   # approximation - works mostly but not 27-01-2009 - 02-02-2009!!
        flow_type  = 'af' if old_prot.lower()=='bt' else 'cf' if old_prot.lower()=='tcp' else None
        gs = GlasMeasurement(direction, port_type, flow_type,tcp_port=old_port)
        gs.oldstyle = True
        gs.ts_start = ts
        gs.ts_end   = None
        gs.srv_b = None
        gs.srv_t = None
        gs.cli_b = None
        gs.cli_t = None
        gs.rst_sent = 0
        gs.srv_rst  = 0
        gs.cli_rst  = 0
        return gs

    def oldstyle1_server_transfer(self, ts, srv_b, srv_t, sbps, fail=False):
        self.ts_end = ts
        self.srv_b = int(srv_b)
        self.srv_t = srv_t

    def oldstyle1_transfer_abort(self, ts):
        self.ts_end = ts
        self.srv_t = 0.0      # we used to set flags, now we simply set time to 0, like MPI

    def oldstyle1_client_speed(self, cli_b, cli_t):
        self.cli_b = cli_b
        self.cli_t = cli_t

    def oldstyle1_server_reset_seen(self, srv_rst, rst_sent):
        self.srv_rst = srv_rst
        self.rst_sent = rst_sent

    def oldstyle1_client_reset_seen(self):
        self.cli_rst = 1

    ##########################################################

    def client_data_1(self,bps,length_ms,resets):
        self.cli_t     = float(length_ms) /1000.0
        self.cli_b     = int(bps)*self.cli_t/8  if str(bps)!='reset' else 0
        self.cli_rst   = int(resets)
        return self

    def server_data_1(self,bps,length,resets,resets_sent):
        self.srv_t     = float(length) if float(length)>=0 else 0.0 # GLASNOST-ERROR: negative times errors in summary-fields
        self.srv_b     = int(bps)*self.srv_t/8
        self.srv_rst   = int(resets)
        self.rst_sent  = int(resets_sent)
        return self

    def client_data_2(self,bytes,length,resets):
        self.cli_b     = int(bytes) if self.dir=='d' else None
        self.cli_b_dbg = int(bytes) if self.cli_b is None else None
        self.cli_t     = float(length)
        self.cli_rst   = int(resets)
        return self

    def server_data_2(self,bytes,length,resets,resets_sent):
        self.srv_b     = int(bytes) if self.dir=='u' else None
        self.srv_b_dbg = int(bytes) if self.srv_b is None else None
        self.srv_t     = float(length)
        self.srv_rst   = int(resets)
        self.rst_sent  = int(resets_sent)
        return self

    ##########################################################

    def __repr__(self):
        rst     = '*'   if self.rst_sent or self.cli_rst or self.srv_rst else ''
        speed = '%7.1f kbps' % self.speed() if self.speed() is not None else '---'
        return "%s/%s/%s\t%s\t(srv: %s in %s\tcli: %s in %s)\t%srst: %s,%s,%s\n"  % \
               (self.dir, self.port, self.proto, speed, self.srv_b, self.srv_t, self.cli_b, self.cli_t, rst, self.rst_sent, self.srv_rst, self.cli_rst)


    def speed(self):
        if self.dir == 'd':
            # assertion: we do get <0 in v1-logs - an error. this checks that it doesn't cause negative speeds
            assert not self.cli_t or self.cli_t >0, "negative client speed"
            return None if not self.cli_t else self.cli_b*0.008/self.cli_t
        if self.dir == 'u':
            assert not self.srv_t or self.srv_t>0, "negative server speed"
            return None if not self.srv_t else self.srv_b*0.008/self.srv_t
        #

    def is_broken(self):
        return self.duration()==0 or self.speed()==0

    def duration(self):
        dur = self.cli_t if self.dir=='d' else self.srv_t
        assert dur>=0
        return dur

    def flow(self):
        return (self.dir, self.port, self.proto)
#


