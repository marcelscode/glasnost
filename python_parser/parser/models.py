# Glasnost Parser v2.
# Developed 2011/2012 by Hadi Asghari (http://deeppacket.info)

from datetime import datetime
import re
from django.db import models


class GlasTest(models.Model):
    """Information extractable about Glasnost Tests before actually processing them"""
    start_time  = models.DateTimeField()
    client_ip   = models.CharField(max_length=20)
    cc          = models.CharField(max_length=2, default='--')
    asn         = models.IntegerField(default=0)
    num_flows   = models.SmallIntegerField()
    client_sum  = models.TextField(null=True)
    server_sum  = models.TextField(null=True)
    proto       = models.CharField(max_length=20, null=True)
    test_done   = models.BooleanField()
    runtime     = models.PositiveIntegerField()
    mlab_server = models.CharField(max_length=15)
    sysinfo     = models.TextField(null=True)
    skip_this   = models.BooleanField()
    created     = models.DateTimeField(default=datetime.now())
    notes       = models.TextField(null=True)
    skip_reason = models.TextField(null=True)

    class Meta:
        unique_together = ('start_time', 'client_ip', 'mlab_server')
        db_table = 'glasnost_test'

    @staticmethod
    def factory(ti):
        skip = False if ti['done']==1 else True # default value
        skip_reason = None if ti['done']==1 else 'Not Done' # default value
        obj  = GlasTest(
            client_ip   = ti['client_ip'],
            start_time  = ti['start_time'],
            num_flows   = ti['num_flows'],
            client_sum  = ti['client_sum'],
            server_sum  = ti['server_sum'],
            proto       = ti['proto'],
            test_done   = ti['done'],
            cc          = ti.get('cc','--'),
            asn         = ti.get('asn',0),
            runtime     = ti['runtime'],
            mlab_server = ti['mlab_server'],
            sysinfo     = ti['sysinfo'],
            skip_this   = skip,
            skip_reason = skip_reason
            )
        return obj
    #

    def __repr__(self):
        return "GlasTest object with id: " + str(self.id)


class GlasVerdict(models.Model):
    """Verdicts, warnings, and some details of a test"""

    test = models.OneToOneField(GlasTest)
    # informative
    port_app = models.IntegerField()
    port_neu = models.IntegerField()
    duration = models.IntegerField(null=True)
    max_up   = models.FloatField(null=True)
    max_dn   = models.FloatField(null=True)
    # verdicts
    appdiff_up  = models.CharField(max_length=5,blank=True)    # throt/noisy/ok
    appdiff_dn  = models.CharField(max_length=5,blank=True)
    portdiff_up = models.CharField(max_length=5,blank=True)   # throt/noisy/ok
    portdiff_dn = models.CharField(max_length=5,blank=True)
    failedv_up  = models.CharField(max_length=6,blank=True)   # ''/mnoisy/dpi/port
    failedv_dn  = models.CharField(max_length=6,blank=True)
    has_forgrst = models.BooleanField()
    verdict     = models.CharField(max_length=5)       # 'OK', 'OK1/2', 'DPI', 'PORT', 'UNDEF'
    undef_reason= models.TextField(blank=True)
    # warnings
    w_btfaster    = models.BooleanField()
    w_strangediff = models.BooleanField()
    w_cfnpfail    = models.BooleanField()
    w_fail2x      = models.BooleanField()
    w_broken      = models.BooleanField()
    w_portchange  = models.BooleanField()
    #
    created       = models.DateTimeField(default=datetime.now())

    class Meta:
        db_table = db_table = 'glasnost_verdict'

    @staticmethod
    def factory(test, tinfo, r, w):
        assert r['u_app_diff']  in (None,'throt','noisy','ok')
        assert r['u_port_diff'] in (None,'throt','noisy','ok')
        assert r['u_failv']     in (None,'','fnoisy','fdpi','fport')

        obj = GlasVerdict(
            test = test,
            port_app = tinfo['port_app'],
            port_neu = tinfo['port_neu'],
            duration = tinfo.get('duration',None),
            max_up = round(tinfo['maxup'],1) if tinfo['maxup'] else None,
            max_dn = round(tinfo['maxdn'],1) if tinfo['maxdn'] else None,
            appdiff_up  = r['u_app_diff'] or '',
            appdiff_dn  = r['d_app_diff'] or '',
            portdiff_up = r['u_port_diff'] or '',
            portdiff_dn = r['d_port_diff'] or '',
            failedv_up  = r['u_failv'] or '',
            failedv_dn  = r['d_failv'] or '',
            has_forgrst = r['has_forgrst'] or False,
            verdict     = r['verdict'],
            undef_reason= r['vreason'] or '',
            w_btfaster    = w['w_btfaster'],
            w_strangediff = w['w_strangediff'],
            w_cfnpfail    = w['w_cfnpfail'],
            w_fail2x      = w['w_fail2x'],
            w_broken      = w['w_broken'],
            w_portchange  = w['w_portchange'],
        )
        return obj
    #


class GlasVerdict_i(models.Model):
    """Interim calculations for the test verdicts"""
    test = models.OneToOneField(GlasTest)
    iu_failed = models.TextField()
    id_failed = models.TextField()
    iu_failed_full = models.TextField()
    id_failed_full = models.TextField()
    iu_ad1 = models.CharField(max_length=4,blank=True)  # fail/nois/Y/N
    iu_ad2 = models.CharField(max_length=4,blank=True)
    iu_pd1 = models.CharField(max_length=4,blank=True)
    iu_pd2 = models.CharField(max_length=4,blank=True)
    id_ad1 = models.CharField(max_length=4,blank=True)
    id_ad2 = models.CharField(max_length=4,blank=True)
    id_pd1 = models.CharField(max_length=4,blank=True)
    id_pd2 = models.CharField(max_length=4,blank=True)
    i_btafaster   = models.BooleanField()
    i_btpfaster   = models.BooleanField()
    i_strangedif1 = models.BooleanField()
    i_strangedif2 = models.BooleanField()
    i_appverdict  = models.CharField(max_length=5,blank=True)  # dpi/noisy/ok
    i_portverdict  = models.CharField(max_length=5,blank=True) # port/noisy/ok
    created     = models.DateTimeField(default=datetime.now())

    class Meta:
        db_table = db_table = 'glasnost_verdict_i'

    @staticmethod
    def factory(test, i):
        obj = GlasVerdict_i(
            test = test,
            iu_failed = re.sub('#[0-9]r[0-9]','',i['iu_failed']),
            id_failed = re.sub('#[0-9]r[0-9]','',i['id_failed']),
            iu_failed_full = i['iu_failed'],
            id_failed_full = i['id_failed'],
            iu_ad1 = i.get('iu_ad1','')[:4],
            iu_ad2 = i.get('iu_ad2','')[:4],
            iu_pd1 = i.get('iu_pd1','')[:4],
            iu_pd2 = i.get('iu_pd2','')[:4],
            id_ad1 = i.get('id_ad1','')[:4],
            id_ad2 = i.get('id_ad2','')[:4],
            id_pd1 = i.get('id_pd1','')[:4],
            id_pd2 = i.get('id_pd2','')[:4],
            i_btafaster = i['i_btafaster'],
            i_btpfaster = i['i_btpfaster'],
            i_strangedif1 = i['i_strangedif1'],
            i_strangedif2 = i['i_strangedif2'],
            i_appverdict  = i.get('i_appverdict',''),
            i_portverdict = i.get('i_portverdict',''),
        )
        return obj
    #