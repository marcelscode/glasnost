# Glasnost Parser v2.
# Created 08-nov-2011 by Hadi Asghari (http://deeppacket.info)
#
import gzip, os, time, re, sys, datetime
from glasMeasure import GlasMeasurement

pre_start  = re.compile('(\d{13}) Client (.+) ([0-9.]+) connect')
pre_replay = re.compile(r'Received: replay (.+) as')

def pre_parse_log(fl):
    """PREPARSER"""
    ti = {
        'start_time': None,
        'client_ip': None,
        'client_sum': None,
        'server_sum': None,
        'num_flows': 0,
        'proto': None,
        'done' : False,
        'runtime': 0,
        'mlab_server': None,
        'sysinfo': None
        } # test-info

    if os.path.getsize(fl)==0:
        return None
    f = gzip.open(fl) if fl.endswith('.gz') else open(fl)
    try:
        ts0, client_name, ti['client_ip'] = pre_start.match(f.next()).groups()
        ti['start_time']  = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(long(ts0)/1000))
        ti['mlab_server'] = fl.split('/')[-2][:-20] # get server name from directory, and shorten it
        ts1 = None

        for s in f:
            if s=='\n':
                continue

            ts1, line = s[:14], s[14:-1]
            if  line.startswith('Client: http'):
                 ti['client_sum'] = line[12:]
            elif line.startswith('http'):
                 ti['server_sum'] = line[4:]
            elif line.startswith('Done.') and ti['server_sum'] and ti['client_sum']:
                ti['done'] = True
            elif line.startswith('Done.') and ti['start_time'][:4]=='2009':
                ti['done'] = True # on log-v1 files, the server & client summary strings are not necessary
            elif line.startswith('Received:'):
                if  not 'setup' in line:
                    ti['num_flows'] += 1
                if not ti['proto']:
                    m = pre_replay.match(line)
                    if m:
                        ti['proto'] = m.group(1)[:20] #truncate at 20
                    elif 'bt downstream' in line:
                        ti['proto'] = 'BitTorrent (v1-log)'
                #
            elif line.startswith('Client: Sysinfo:'):
                ti['sysinfo'] = line[17:]
            #
        #
        if ts1:
            ti['runtime'] = (long(ts1)-long(ts0))/1000 if 1000000>(long(ts1)-long(ts0))>=0 else 0

    except Exception as x:
        print >>sys.stderr, '!!  parse_log_keyparts() err: %s ' % (x)
        return None
    else:
        return ti
    finally:
        f.close()


def parse_summary_string_log2(client_sum, server_sum):
    info = {'port_app':None, 'port_neu':None, 'duration': None, 'maxup':None, 'maxdn':None}
    client_sum = client_sum.strip()
    server_sum = server_sum.strip()

    kv = { x.split('=')[0]:x.split('=')[1] for x in client_sum.split('&') if x!=''}
    kvs = { x.split('=')[0]:x.split('=')[1] for x in server_sum.split('&') if x!=''}
    kv.update(kvs)
    del kvs

    # extract general fields
    repeat   = int(kv['repeat'])
    protocol = kv['expprot0']
    info['port_app'] = int(kv['expp0'])
    info['port_neu'] = int(kv['expp18']) #
    info['duration'] = int(kv['duration'])

    # make sure we have a 'usable' test
    assert kv['done']=='yes'
    assert repeat==3 and kv['up']=='true' and kv['down']=='true'  # measurements = repeat *2*2*2
    if info['duration']!=20:
        print >>sys.stderr, "!! DURATION = %d !!"%info['duration']
    #assert info['duration']==20
    #confirm_flow_directions_log2(kv, repeat)  # in rare cases the up & down flows are reversed -- this function warns if so. doesn't really matter though.

    measurements = []
    # - 6x upload from the client to the server on an application-specific port, interleaving transfers emulating application traffic and traffic with random bytes
    # - 6x upload from the client to the server on a neutral port, interleaving transfers emulating application traffic and traffic with random bytes
    # - 6x download of the client from the server on an application-specific port, interleaving transfers emulating application traffic and traffic with random bytes
    # - 6x download of the client from the server on a neutral port, interleaving transfers emulating application traffic and traffic with random bytes
    for n in range(0,8):
        di    = 'u' if n<4 else 'd'
        port  = 'ap' if n in (0,1,4,5) else 'np'
        proto = 'af' if n%2 ==0 else 'cf'
        for i in range(repeat):
            ii = (n/2)*6 + n%2 + i*2        # this magic formula is from mpi_detector.pl. loop can be simpler but i keep this to make cross-code comparisons easier

            assert (proto=='cf') == ('cf' in kv['expprot%d'%ii])
            assert (di=='u' and kv['expserv%d'%ii]=='client') or (di=='d' and kv['expserv%d'%ii]=='server')
            assert kv['expl%d'%ii]!=0 or kv['expsl%d'%ii]!= 0  # we expect either expl or expsl to exist

            stream1 = GlasMeasurement(di, port, proto, tcp_port=kv['expp%d'%ii])
            stream1.client_data_2(kv['expd%d'%ii],  kv['expl%d'%ii],  kv.get('expr%d'%ii,0))
            stream1.server_data_2(kv['expsd%d'%ii], kv['expsl%d'%ii], kv.get('expsr%d'%ii,0), kv.get('expsrs%d'%ii,0) )
            measurements.append(stream1)
    #

    info['maxup'] = max(x.speed() for x in measurements if x.dir=='u')
    info['maxdn'] = max(x.speed() for x in measurements if x.dir=='d')
    return (measurements, info)


#def confirm_flow_directions_log2(kv, repeat):
#    # Decide which of the flows are uploads and which are downloads
#    # This code is more general than necessary, but will then also work for user-generated tests
#    # copied & adapted from MPI's detector.pl
#    di = [None,None]
#    uncertainty = 0
#    for n in range(2):
#        up,down = 0,0
#        for i in range(repeat*4):
#            ii = n*repeat*4+i
#            if int(kv['expd%d'%ii]) > int(kv['expsd%d'%ii]):
#                down += 1
#            elif int(kv['expd%d'%ii]) < int(kv['expsd%d'%ii]):
#                up += 1
#            else: # use default
#                if n==0: up+=1
#                else:    down+=1
#        #
#        if up>down:
#            di[n] = 'u'
#        elif up<down:
#            di[n] = 'd'
#        elif n==0:
#            di[n] = 'u'
#        else:
#            di[n] = 'd'
#        # There should be the same number of uploads and downloads
#        if up != down:
#            uncertainty = max(uncertainty, 1.0/abs(up-down))  ## WTF! is this?!
#        else:
#            uncertainty = 1
#    #
#    if di[0]==di[1]  or uncertainty > (1.0/repeat): # Fall back to defaults
#        di[0], di[1] = 'u', 'd'
#    #
#    if not (di[0]=='u' and di[1]=='d'):
#        print >>sys.stderr, "   !!%s test directions reverse (%s)!!" % (kv['peer'],kv['protocol1'])
#    #

