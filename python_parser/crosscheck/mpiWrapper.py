import os
import re
import shlex
import subprocess
import time
from models import Detection_Result

class mpiWrapper:

    def __init__(self):
        PERL = 'perl' # 'c:\\cygwin\\bin\\perl.exe' # os-dependent
        cmd = [PERL, os.path.join(os.path.realpath(os.path.dirname(__file__)),'glasnost_differentiation_detector_me.pl').replace('D:','/cygdrive/d').replace('\\','/')]
        self.process = subprocess.Popen(cmd, stdin=subprocess.PIPE,  stdout=subprocess.PIPE)

    def analyze(self, test):
        self.process.stdin.write("%d;%s;-;%s;%s;DIR;FILE\n" % (time.mktime(test.start_time.timetuple()),test.client_ip,test.client_sum,test.server_sum))
        self.process.stdin.flush()
        out = self.process.stdout.readline()
        mpi_result = Detection_Result(test=test,script_output=out)
        vals = shlex.split( out )
        if vals[0] != 'STDERR':
            for s in vals[3:]:
                m1 = re.match('(upload|download) (port|BitTorrent) (noisy|throttled|OK)', s)
                m2 = re.match('(\d+) (Control flow|BitTorrent) (upload|download) port (\d+) (failed|blocked)', s)
                if m1:
                    di,typ,res = m1.groups()
                    if di=='upload' and typ=='BitTorrent':
                        mpi_result.up_app_diff =  res[:5].lower()
                    elif di=='upload' and typ=='port':
                        mpi_result.up_port_diff =  res[:5].lower()
                    elif di=='download' and typ=='BitTorrent':
                        mpi_result.dn_app_diff =  res[:5].lower()
                    elif di=='download' and typ=='port':
                        mpi_result.dn_port_diff =  res[:5].lower()
                    else:
                        raise LookupError() # debug
                #
                elif m2:
                    num,flw,di,port,typ = m2.groups()
                    flw = 'cf' if flw=="Control flow" else 'bt' if flw=="BitTorrent" else 'f?'
                    port = 'bt' if 6880<=int(port)<=6889 else 'ne' if int(port)>=10000 else 'p?'
                    if di=='upload':
                        mpi_result.up_failed += '(%s:%s)'%(flw,port)
                    else:
                        mpi_result.dn_failed += '(%s:%s)'%(flw,port)
                #
                else:
                    raise Exception('unknown output: %s' % s)
        #
        else:
            mpi_result.error = " ".join(vals[3:])

        return mpi_result


    def close(self):
        out,err = self.process.communicate()
        assert err is None and out=="" # no lingering stuff
        self.process = None