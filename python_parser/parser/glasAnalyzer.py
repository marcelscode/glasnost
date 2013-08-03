# Glasnost Parser v2.
# Developed 2011/2012 by Hadi Asghari (http://deeppacket.info)
#
# Module that analyzes stream statistics for one single Glasnost test ,
# and returns back verdicts (about throlttling/blocking), plus warnings & debug info

import itertools
import math
from operator import xor


class Flow:
    """ measurements of same type grouped together"""

    def __init__(self, type, measurements):
        self.type     = type # tuple of direction, port, and protocol (u/d, ap/np, af/cf)
        self.measurements = measurements

    def direction(self):
        return self.type[0]

    def is_noisy(self):
        NOISE_THRESHOLD  = 0.2
        return self.noise > NOISE_THRESHOLD

    def is_slower_than(self, flow2):
        assert self.count_measures()>=2, "is_slower_than()"
        DIFFER_THRESHOLD = 0.2 if len(self.measurements)>2 else 0.5
            # note: can set higher thresholds, i.e. THRESH = 0.3 if required (seems not necessary)
            # todo: need to validate the 0.5 for repetitions =2 cases. for nodata it was not a good idea!
        return abs(self.max-flow2.max)/max(self.max,flow2.max) > DIFFER_THRESHOLD and self.max<flow2.max

    def is_faster_than(self, flow2):
        assert self.count_measures()>=2
        DIFFER_THRESHOLD = 0.2 if len(self.measurements)>2 else 0.5
        return abs(self.max-flow2.max)/max(self.max,flow2.max) > DIFFER_THRESHOLD and self.max>flow2.max

    def count_measures(self):
        return len(self.measurements) - self.nodata

    def has_failed(self):
        # if we have 1 or less measurements, we consider this too unreliable for differentiation comparison
        return self.count_measures() < 2

    def has_nodata_or_rst(self):
        return self.nodata>0 or self.rstblock>0

    def pre_compute(self):
        """Get noise and max throughput for each flow type."""
        self.max      = 0 # maximum speed in flow measurements
        self.noise    = 0 # noise level in flow
        self.rstblock = 0 # forged tcp-resets
        self.nodata   = 0 # connection never started or stalled (time=0 or bytes=0)

        # NOTE: the MPI script exits on this condition, not sure why. condition hits in V1 logs but not V2
        # if any(not m.srv_t and not m.cli_t for m in self.measurements)...

        # get speeds of non-broken measurements.
        # a broken measurement, or nodata, is when either (a) duration is zero or (b) transfer-bytes is zero.
        bps = [m.speed() for m in self.measurements if not m.is_broken()]

        for m in self.measurements:
            if m.cli_rst > 0 and m.srv_rst > 0 and not m.rst_sent:
                # NOTE: there was an additional  "m.duration<DURATION" clause in MPI scripts, not sure why (in v2 logs <21.01 holds)
                self.rstblock += 1

        self.nodata = len(self.measurements) - len(bps)

        if bps:
            self.max = max(bps)
            assert self.max > 0, "bps all zero"
            mid = sorted(bps)[int(math.floor(len(bps) * 0.5))]
            self.noise = (self.max - mid) / self.max
        #else: all three measurements of a flow are "broken". can't measure speed for this flow
    #

    def has_port_change(self):
        return sum(m.tcp_port for m in self.measurements) != float(len(self.measurements)) * self.measurements[0].tcp_port
#



def glasnost_analysis_v2(measurements):
    """Analyze streams of a test for signs of traffic differentiation and port blocking.
        Input: measurement streams
        Output: (r,i), both are dictionaries. r includes results and warnings; i has interim calcs"""

    # PREPARE:
    # group repeated measurements into flows, and do pre-computations
    # flow 0: upstream app_port application
    # flow 1: upstream app_port control
    # flow 2: upstream neu_port application
    # flow 3: upstream neu_port control
    # flow 4: downstream app_port application
    # flow 5: downstream app_port control
    # flow 6: downstream neu_port application
    # flow 7: downstream neu_port control
    flows = {}
    for type in  itertools.product(['u','d'],['ap','np'],['af','cf']):
        ms = [m for m in measurements if m.flow()==type]
        if ms: flows[type] = Flow(type,ms)

    repeat = len(measurements)/len(flows)
    dirs   = set([f.direction() for f in flows.values()])

    if repeat not in (2,3,5):
        raise Exception('invalid repetition: %d' % repeat)
    for f in flows.values():
        if len(f.measurements) != repeat:
            raise Exception("flows badly matched!!")
    #

    for f in flows.values():
        f.pre_compute()


    r = {  # results
        'u_app_diff': None, 'u_port_diff': None, 'd_app_diff': None, 'd_port_diff': None,
        'u_failv': None,    'd_failv': None,     'has_forgrst': None, 'verdict': None,     'vreason': None  }
    w = {  # warnings
        'w_btfaster': False, 'w_strangediff': False, 'w_cfnpfail': False, 'w_broken': False, 'w_fail2x': False, 'w_portchange': False }
    i = {  # interim calculations
        'iu_failed': '',  'id_failed' : '', 'i_btafaster': False,   'i_btpfaster': False,
        'i_strangedif1': False, 'i_strangedif2': False }        # and more e.g.: 'iad1_u'

    w['w_fail2x'] = any(f.has_failed() for f in flows.values())
    w['w_broken'] = any(f.count_measures()==0 for f in flows.values())
    w['w_portchange'] = any(f.has_port_change() for f in flows.values() if f.type[1]=='ap')  

    # BLOCKING (forged tcp or no-data)
    # interim calculations
    i['iu_failed'] = ''
    i['id_failed'] = ''
    for f in flows.values():
        if f.rstblock>0 or f.nodata>0:
            flw  = 'cf' if f.type[2]=='cf' else 'bt' if f.type[2]=='af' else 'f?'
            prt  = 'ne' if f.type[1]=='np' else 'bt' if f.type[1]=='ap' else 'p?'
            i['i%s_failed'%f.type[0]] += '(%s:%s#%dr%d)' %(flw,prt,f.nodata,f.rstblock)

    # blocking-results
    r['has_forgrst'] = any(f.rstblock>0 for f in flows.values())
    for di in dirs:
        if flows[di,'np','cf'].has_nodata_or_rst():
            # control flow on neutral port should never fail. this is truly noise, bad configuration, etc
            r[di+"_failv"] = 'fnoisy'
            w['w_cfnpfail'] = True
        elif flows[di,'ap','af'].has_nodata_or_rst():
            # (bt:bt) indicates blocking, now if also on neutral port, than dpi, otherwise, port-based
            #         note that for port-based, we expect (cf:bt) too. classification of it's absence is in debate
            r[di+"_failv"] = 'fdpi' if flows[di,'np','af'].has_nodata_or_rst() else 'fport'
        elif flows[di,'np','af'].has_nodata_or_rst() or flows[di,'ap','cf'].has_nodata_or_rst():
            # three cases : all noise. the categorization of the lone (bt:ne) is still in debate.
            r[di+"_failv"] = 'fnoisy'
        else:
            r[di+"_failv"] = ""

        assert not xor (i['i%s_failed'%di]=="", r["%s_failv"%di]=="") # to catch unhandled cases above
    #

    # DIFFERENTIATING (throttling)
    # interim calculations
    for di in dirs:
        # flows 0&1: protocol1 upstream port1 AND protocol2 upstream port1
        if flows[di,'ap','af'].has_failed() or flows[di,'ap','cf'].has_failed():i['i%s_ad1'%di] = 'fail'
        elif flows[di,'ap','af'].is_noisy() or flows[di,'ap','cf'].is_noisy():  i['i%s_ad1'%di] = 'noise'
        elif flows[di,'ap','af'].is_slower_than(flows[di,'ap','cf']):           i['i%s_ad1'%di] = 'Y'
        else:
            i['i%s_ad1'%di] = 'N'
            if flows[di,'ap','af'].is_faster_than(flows[di,'ap','cf']): i['i_btafaster']= True

        # flows 2&3: protocol1 upstream port2 AND protocol2 upstream port2
        if flows[di,'np','af'].has_failed() or flows[di,'np','cf'].has_failed(): i['i%s_ad2'%di] = 'fail'
        elif flows[di,'np','af'].is_noisy() or flows[di,'np','cf'].is_noisy():   i['i%s_ad2'%di] = 'noise'
        elif flows[di,'np','af'].is_slower_than(flows[di,'np','cf']):            i['i%s_ad2'%di] = 'Y'
        else:
            i['i%s_ad2'%di] = 'N'
            if flows[di,'np','af'].is_faster_than(flows[di,'np','cf']): i['i_btafaster'] = True

        # flows 0&2: protocol1 upstream port1 AND protocol1 upstream port2
        if flows[di,'ap','af'].has_failed() or flows[di,'np','af'].has_failed(): i['i%s_pd1'%di] = 'fail'
        elif flows[di,'ap','af'].is_noisy() or flows[di,'np','af'].is_noisy():   i['i%s_pd1'%di] = 'noise'
        elif flows[di,'ap','af'].is_slower_than(flows[di,'np','af']):            i['i%s_pd1'%di] = 'Y'
        else:
            i['i%s_pd1'%di] = 'N'
            if flows[di,'ap','af'].is_faster_than(flows[di,'np','af']): i['i_btpfaster'] = True

        # flows 1&3: protocol2 upstream port1 AND protocol2 upstream port2
        if flows[di,'ap','cf'].has_failed() or flows[di,'np','cf'].has_failed(): i['i%s_pd2'%di] = 'fail'
        elif flows[di,'ap','cf'].is_noisy() or flows[di,'np','cf'].is_noisy():  i['i%s_pd2'%di] = 'noise'
        elif flows[di,'ap','cf'].is_slower_than(flows[di,'np','cf']):            i['i%s_pd2'%di] = 'Y'
        else:
            i['i%s_pd2'%di] = 'N'
            if flows[di,'ap','cf'].is_faster_than(flows[di,'np','cf']): i['i_btpfaster'] = True
    #

    # differentiation-results
    for di in dirs:
        # App-based: combine idiff_app_1_u  & idiff_app2_u
        if i['i%s_ad1'%di] in ('noise','fail') and i['i%s_ad2'%di] in ('noise','fail'):
            # both (noise/fail) -> noisy
            r[di+'_app_diff'] = 'noisy'
        elif i['i%s_ad1'%di]=='Y' or i['i%s_ad2'%di]=='Y':
            # at least one is 'Y' -> throttle (if the other is N: warn)
            r[di+'_app_diff'] = 'throt'
            if  i['i%s_ad1'%di]=='N' or i['i%s_ad2'%di]=='N':  i['i_strangedif1'] = True
        else:
            # one is N and the other (N/noisy/fail) -> OK
            r[di+'_app_diff'] = 'ok'

        # Port-based: combine idiff_port_1_u & idiff_port2_u ...
        if i['i%s_pd1'%di] in ('noise','fail') and i['i%s_pd2'%di] in ('noise','fail'):
            r[di+'_port_diff'] = 'noisy'
        elif i['i%s_pd1'%di]=='Y' or i['i%s_pd2'%di]=='Y':
            r[di+'_port_diff'] = 'throt'
            if i['i%s_pd1'%di]=='N' or i['i%s_pd2'%di]=='N':  i['i_strangedif2'] = True
        else:
            r[di+'_port_diff'] = 'ok'
    #

    w['w_btfaster'] = i['i_btafaster'] or i['i_btpfaster']
    w['w_strangediff'] = i['i_strangedif1'] or i['i_strangedif2']

    # FINAL COMBINED VERDICT
    if r['u_app_diff']=='throt' or r['d_app_diff']=='throt' or r['u_failv']=='fdpi' or r['d_failv']=='fdpi':
        app_verdict = 'dpi'
    elif r['u_app_diff']=='noisy' or r['d_app_diff']=='noisy' or r['u_failv']=='fnoisy' or r['d_failv']=='fnoisy':
        app_verdict = 'noisy'  # ok + noisy = noisy
    else:
        app_verdict = 'ok'

    if r['u_port_diff']=='throt' or r['d_port_diff']=='throt' or r['u_failv']=='fport' or r['d_failv']=='fport':
        port_verdict = 'port'
    elif r['u_port_diff']=='noisy' or r['d_port_diff']=='noisy' or r['u_failv']=='fnoisy' or r['d_failv']=='fnoisy':
        port_verdict = 'noisy'
    else:
        port_verdict = 'ok'

    i['i_appverdict']  = app_verdict
    i['i_portverdict'] = port_verdict

    if app_verdict=='dpi':
        r['verdict'] = 'DPI'
    elif port_verdict=='port':
        r['verdict'] = 'PORT'
    elif app_verdict==port_verdict=='ok':
        r['verdict'] = 'OK'
    elif (app_verdict=='ok' and port_verdict=='noisy') or (port_verdict=='ok' and app_verdict=='noisy'):
        r['verdict'] = 'OK1/2'         # note: noisy + OK was 'undef'... OK1/2 makes it more transparent
    else:
        assert app_verdict==port_verdict=='noisy'
        r['verdict'] = 'UNDEF'
        r['vreason']  = 'nosiy measurements'

    if len(dirs)==1 and r['verdict']=='OK':
        # for single directional tests, we cannot be sure
        r['verdict'] = 'UNDEF'
        r['vreason']  = 'uni-directional test'

    if w['w_portchange'] and r['verdict']=='PORT':
        # for tests where the application-port has changed during the test, the port verdicts are unreliable. 
        # NOTE: possible error: 'OK' verdicts might also be missing PORT blocking and the only correct verdict is 'DPI'; (this also depends on number of blocks.)
        r['verdict'] = 'UNDEF'
        r['vreason']  = 'port changed in test'

    return r,w,i
#

