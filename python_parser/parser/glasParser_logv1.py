# Glasnost Parser v2.
# Developed 2011/2012 by Hadi Asghari (http://deeppacket.info)

import time
import os,sys, glob
from datetime import datetime, timedelta
from glasMeasure import GlasMeasurement


def get_log_name(GLASNOST_ROOT, start_time, client_ip, mlab_server):
    """Helper method that given a test key, finds the logfile"""

    log_glob = "%s/%s.measurement-lab.org/%s_%s_*" %   (start_time.strftime('%Y/%m/%d'), mlab_server, start_time.strftime('%Y-%m-%dT%H:%M:%S'), client_ip)
    if start_time < datetime(2010,1,8,5,7,0): 
        # before this time, the days are +1 in the filenames
        dy = start_time.day + 1
        log_glob = log_glob[:8] + '%02d'%dy + log_glob[10:]
        log_glob = log_glob[:51] + '%02d'%dy + log_glob[53:]
    if not sys.platform.startswith("linux"):
        log_glob = log_glob.replace(':','_')

    logs = glob.glob(os.path.join(GLASNOST_ROOT, log_glob))
    if not logs:
        # sometimes filename seconds differs by +/-1! change to wildcard
        log_glob = log_glob[:61] + '?' + log_glob[62:]
        logs = glob.glob(os.path.join(GLASNOST_ROOT, log_glob))
        if not logs:
            log_glob = log_glob[:60] + '?' + log_glob[61:]
            logs = glob.glob(os.path.join(GLASNOST_ROOT, log_glob))
    #endif
    if len(logs)!=1:
        raise Exception('!! log file not found (=%d): %s' % (len(logs),log_glob))
    return logs[0]


def parse_log_oldstyle1(fl):
    """ This method has been copied from Glasnost_Parser_1.6, with some modifcations to make it fit here
         Returns: (measurements, testinfo) or Exception on error """

    ti = {
        'mlab_server': None, 'client_ip': None, 'start_time': None,
        'num_flows': 0,  'done' : False, 'runtime': 0, 'sysinfo': None,
        'port_app':None, 'port_neu':None, 'maxup':None, 'maxdn':None
    } # test-info

    fl = fl.replace('\\','/')
    ti['mlab_server'] = fl.split('/')[-2][:-20]
    tt = fl.split('/')[-1]
    log_dt, log_tm, ti['client_ip'], log_host = tt[:10], tt[11:19], tt[19:].split('_',2)[1], tt[19:].split('_',2)[-1][:-4]

    # skip zero size files and some other untamable corrupt files
    log_sz = os.path.getsize(fl)
    if log_sz==0:
        raise Exception('zero file')

    if tt in ['2009-12-03T06:21:24_201.81.164.165_c951a4a5.virtua.com.br.log', '2009-12-26T21:27:03_166.137.138.15_mobile-166-137-138-015.mycingular.net.log']:
        # manually exclude some problematic logs
        raise Exception('manually excluded')

    f1 = open(fl)
    buff = f1.readlines()
    f1.close()

    # Begin Parsing:  start by verifying file header... this format used up to 2010-04-20
    #    <timestamp> Client 189.89.21.133 189.89.21.133 connected (port 2265)
    #    <timestamp> Using ports 6881 and 10009 for measurements.
    try:
        timest1, dum, client_name, client_ip, dum = buff[0].split(' ', 4)
        dum, dum, dum, bttpo, dum, tcppo, dum = buff[1].split(' ', 6)
        timest1, ti['port_app'], ti['port_neu'] = int(timest1), int(bttpo), int(tcppo)
        assert client_ip==ti['client_ip'] and client_name==log_host
        ti['start_time'] = time.strftime('%Y-%m-%d %H:%M:%S',time.gmtime(timest1/1000))
    except Exception as ex:
        # corrupted log - file has bad header (in most cases indicative of logs with dual-clients)
        raise Exception('bad header')


    # main loop in file: process per stream information - (24 or 16 measurements)
    # these are: down/up (2x) random/bt traffic (2x) random/bt port (2x) repetitions (3x or 2x)
    #     <timestamp> Running <protocol> <direction>stream transfer port <port> .
    #      ....
    #     <timestamp>  Resets: [1] ; Resets sent: [0]
    #     <timestamp> [FAILED]: Transfered 0 bytes in [20.844] seconds: [0] bps
    #     <timestamp> Client: Transfered 0.0 bytes in 20.009 seconds: [0.0] bps (state=[6])
    measurements = []
    astream = None
    is_corrupt = False

    for lineno in range(2,len(buff)-1):  # last line removed from loop to avoid corner cases where file is stopped half-way
        s = buff[lineno]
        ts, keyw, toks = s[:14], s[14:].split(' ',1)[0], s[14:].split(' ')[1:]
        if keyw=='Client:':
            keyw += ' ' + toks[0]
            toks = toks[1:]
        msgpart = s[len(keyw)+15:-1]
        if s[13]!=' ':
            # corrupted log - invalid timestamp in logfile
            is_corrupt = True
            break

        if keyw=='Client':              # note, no  double colon
            # this is a doubled file... possibly a race condition where client opens 2 instances of the test simultaneously and server logs to same file...
            assert buff[lineno+1].split(' ')[1]=='Using' or buff[lineno+2].split(' ')[1]=='Using'
            # corrupted log - invalid logfile with double clients
            is_corrupt = True
            break

        if keyw=='Running':
            # New stream detected...
            if astream:
                # client info for stream missing!
                assert astream.ts_end
                measurements.append(astream)
            astream = GlasMeasurement.oldstyle1_factory(int(ts), toks[0], toks[1], int(toks[4]))

        if keyw=='Resets:':
            assert astream
            astream.oldstyle1_server_reset_seen(int(toks[0]), int(toks[-1]))

        if keyw=="Transfered":
            assert astream
            # stream ends. speed as reported by server
            astream.oldstyle1_server_transfer( int(ts), int(toks[0]), float(toks[3]), float(toks[5]) )

        if keyw=="FAILED:":
            assert astream
            # these are also cases of stream-end, but with some problem
            # debug: I've managed to get these to 'work' (=parse like summary strings). but what does transfer yet fail mean?!
            if toks[0] == "Transfered":
                astream.oldstyle1_server_transfer( int(ts), int(toks[1]), float(toks[4]), float(toks[6]), fail=True)
            else:
                assert msgpart in ('BT downstream transfer','BT upstream transfer', 'TCP downstream transfer', 'TCP upstream transfer')
                astream.oldstyle1_transfer_abort(int(ts))

        if keyw=='Client: FAILED:':
            assert astream
            # this is when client sees reset. The client also reports exceptions etc for logging purposes separately
            assert 'transfer reset' in msgpart
            astream.oldstyle1_client_reset_seen()

        if keyw=="Client: Sysinfo:":  # at end of the log, client's info is given (after mar-19th.)
            assert not astream
            ti['sysinfo'] = msgpart

        if keyw=="Client: Transfered":
            if buff[lineno][:50]==buff[lineno-1][:50]:
                continue    # there were a few cases where this was just preceeded by itself, which would otherwise cause parsing errors..
            assert astream and astream.ts_end # stream end seen
            astream.oldstyle1_client_speed(float(toks[0]), float(toks[3]))
            measurements.append(astream)
            astream = None
            #end-for

    if is_corrupt:
        raise Exception('corrupt log')

    # chunk up last line
    s = buff[-1]
    ts, keyw, toks = s[:14], s[14:].split(' ',2)[0], s[14:].split(' ')[1:]
    if  keyw=='Client:' and len(toks)>0: keyw += ' ' + toks[0]

    ti['runtime'] = (int(ts) - timest1)/1000.0                # in secs
    ti['num_flows'] = len(measurements)

    ups   = [m for m in measurements if m.dir=='u']
    dns   = [m for m in measurements if m.dir=='d']
    ti['maxup'] = max(m.speed() for m in ups) if ups else None
    ti['maxdn'] = max(m.speed() for m in dns) if dns else None

    # wrap-up
    if keyw in ("Done.\n","Zipping", 'http', 'Client: http', 'Client: Sysinfo:', 'Done'):
        if not ( (len(measurements) in (16,24,40) and len(ups)==len(dns)) or (len(measurements)==20 and (not ups or not dns)) ):
            raise Exception('bad flow count: %d+%d'%(len(ups),len(dns)))
        ti['done'] = True
    #else:
    # most probably client closes test mid-way or test is killed /crashes on server
    # sometimes there are no connections at all. files are typically small

    return measurements, ti




# Note: commeneted out, Can be used for V0 logs (2008 - not available on MLabs)
#def parse_summary_string_log1(client_sum, server_sum):
#    info = {'port_app':None, 'port_neu':None, 'duration': None, 'maxup':None, 'maxdn':None}
#    client_sum = client_sum.strip()
#    server_sum = server_sum.strip()
#
#    kv = { x.split('=')[0]:x.split('=')[1] for x in client_sum.split('&') if x!=''}
#    kvs = { x.split('=')[0]:x.split('=')[1] for x in server_sum.split('&') if x!=''}
#    kv.update(kvs)
#    del kvs
#
#    # extract general fields
#    protocol = 'bt1'
#    info['port_app'] = int(kv['btport'])
#    info['port_neu'] = int(kv['port2'])
#    info['duration'] = int(kv['duration'])
#    repeat   = int(kv['repeat'])
#
#    #  make sure we have a 'usable' test
#    assert 6889 >= info['port_app'] >= 6881
#    assert kv['done']=='yes'
#    assert repeat==3 and kv['up']=='true' and kv['down']=='true'  # measurements = repeat *2*2*2
#    assert info['duration']==20
#    # confirm_flow_directions_log1(kv, repeat)  # might be needed, doesn't exist now
#
#    # warning for port changed
#    for i in range(3):
#        ii = i+3
#        assert int(kv['sbtdownp%d'%i]) == int(kv['stcpdownp%d'%i]) == info['port_app']
#        assert int(kv['sbtdownp%d'%ii])== int(kv['stcpdownp%d'%ii])== info['port_neu']
#        assert int(kv['sbtupp%d'%i])   == int(kv['stcpupp%d'%i])   == info['port_app']
#        assert int(kv['sbtupp%d'%ii])  == int(kv['stcpupp%d'%ii])  == info['port_neu']
#
#    measurements = []
#    # - 6x upload from the client to the server on an application-specific port, interleaving transfers emulating application traffic and traffic with random bytes
#    # - 6x upload from the client to the server on a neutral port, interleaving transfers emulating application traffic and traffic with random bytes
#    # - 6x download of the client from the server on an application-specific port, interleaving transfers emulating application traffic and traffic with random bytes
#    # - 6x download of the client from the server on a neutral port, interleaving transfers emulating application traffic and traffic with random bytes
#    # note: direction (up/down), matching, and stream.speed() functions are now all correct - checked
#    for i in range(3):
#        # direction=upload (from client's perspective): server measurements' are only used (and download of that)
#        measurements.append( GlasMeasurement('u','ap','af')\
#        .client_data_1(kv['btup%d'%i], kv['btupl%d'%i], kv.get('btupr%d'%i,0))\
#        .server_data_1(kv['sbtdown%d'%i],kv['sbtdownl%d'%i],kv.get('sbtdownr%d'%i,0),kv.get('sbtdownrs%d'%i,0)) )
#        measurements.append( GlasMeasurement('u','ap','cf')\
#        .client_data_1(kv['tcpup%d'%i], kv['tcpupl%d'%i], kv.get('tcpupr%d'%i,0))\
#        .server_data_1(kv['stcpdown%d'%i],kv['stcpdownl%d'%i],kv.get('stcpdownr%d'%i,0),kv.get('stcpdownrs%d'%i,0)) )
#
#    for i in range(3,6):
#        measurements.append( GlasMeasurement('u','np','af')\
#                    .client_data_1(kv['btup%d'%i], kv['btupl%d'%i], kv.get('btupr%d'%i,0))\
#                    .server_data_1(kv['sbtdown%d'%i],kv['sbtdownl%d'%i],kv.get('sbtdownr%d'%i,0),kv.get('sbtdownrs%d'%i,0)) )
#        measurements.append( GlasMeasurement('u','np','cf')\
#                    .client_data_1(kv['tcpup%d'%i], kv['tcpupl%d'%i], kv.get('tcpupr%d'%i,0))\
#                    .server_data_1(kv['stcpdown%d'%i],kv['stcpdownl%d'%i],kv.get('stcpdownr%d'%i,0),kv.get('stcpdownrs%d'%i,0)) )
#
#    for i in range(3):
#        # direction=download: client's own measurements are just used (and direction download again - receiving end)
#        measurements.append( GlasMeasurement('d','ap','af')\
#                       .client_data_1(kv['btdown%d'%i], kv['btdownl%d'%i], kv.get('btdownr%d'%i,0))\
#                       .server_data_1(kv['sbtup%d'%i],kv['sbtupl%d'%i],kv.get('sbtupr%d'%i,0), kv.get('sbtuprs%d'%i,0)) )
#        measurements.append( GlasMeasurement('d','ap','cf')\
#                       .client_data_1(kv['tcpdown%d'%i], kv['tcpdownl%d'%i], kv.get('tcpdownr%d'%i,0))\
#                       .server_data_1(kv['stcpup%d'%i],kv['stcpupl%d'%i],kv.get('stcpupr%d'%i,0),kv.get('stcpuprs%d'%i,0)) )
#
#    for i in range(3,6):
#        measurements.append( GlasMeasurement('d','np','af')\
#                     .client_data_1(kv['btdown%d'%i], kv['btdownl%d'%i], kv.get('btdownr%d'%i,0))\
#                     .server_data_1(kv['sbtup%d'%i],kv['sbtupl%d'%i],kv.get('sbtupr%d'%i,0),kv.get('sbtuprs%d'%i,0)) )
#        measurements.append( GlasMeasurement('d','np','cf')\
#                     .client_data_1(kv['tcpdown%d'%i], kv['tcpdownl%d'%i], kv.get('tcpdownr%d'%i,0))\
#                     .server_data_1(kv['stcpup%d'%i],kv['stcpupl%d'%i],kv.get('stcpupr%d'%i,0),kv.get('stcpuprs%d'%i,0)) )
#        # note: double check with MPI people if the way that we're matching up/downs is correct.
#    info['maxup'] = max(x.speed() for x in measurements if x.dir=='u')
#    info['maxdn'] = max(x.speed() for x in measurements if x.dir=='d')
#    return (measurements, info)



