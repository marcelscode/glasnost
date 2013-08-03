# Glasnost Parser v2.
# Developed 2011/2012 by Hadi Asghari (http://deeppacket.info)


import os, sys, re, time
from datetime import timedelta, datetime
from django import forms
from django.forms import fields
from django.db import transaction
from django.shortcuts import render_to_response
from django.template.context import RequestContext
from parser.models import GlasTest, GlasVerdict, GlasVerdict_i
from parser.glasAnalyzer import glasnost_analysis_v2
from parser.glasParser import parse_summary_string_log2, pre_parse_log
from parser.glasParser_logv1 import get_log_name, parse_log_oldstyle1
from lib import geoasn
#from crosscheck.mpiWrapper import mpiWrapper
from settings import GEOASN_ROOT, GLASNOST_ROOT


def ProcessLogs(request):
    lst,tsk = [], None
    class ThisForm(forms.Form):
        start_date = fields.DateField(initial='2012-03-01')
        end_date   = fields.DateField(initial='2012-03-31')
        task       = fields.ChoiceField( widget=forms.RadioSelect,
                                  choices=( ('imp', 'Import logs'),
                                            ('geo', 'Update Geo & ASN'),
                                            ('pars','Parse, analyze and store verdicts'),))

    if request.method == 'POST':
        form = ThisForm(request.POST)
        if form.is_valid():
            dt, end, tsk = form.cleaned_data['start_date'], form.cleaned_data['end_date'], form.cleaned_data['task']
            dt = datetime(dt.year,dt.month,dt.day)
            end = datetime(end.year,end.month,end.day)
            stt = time.time()
            # initialize
            if tsk=='geo':
                geodb,asndb,paths = geoasn.geoasn_load(dt, GEOASN_ROOT)
            while dt <= end:
                with transaction.commit_manually():
                    try:
                        # per-day function
                        if tsk=='imp':
                            l = task_import_logs(dt)
                        elif tsk=='geo':
                            l = task_update_geoasn(dt,geodb,asndb,paths)
                        elif tsk== 'pars':
                            l = task_parse_analyze(dt)
                        lst += l
                    except Exception as ex:
                         transaction.rollback()
                         raise ex,None,sys.exc_traceback
                    else:
                        transaction.commit()
                #
                dt += timedelta(days = 1)
                # for the next days, choose a more recent geoasn db (if available)
                if tsk=='geo':
                    if geoasn.geoasn_exists(dt, GEOASN_ROOT):
                        geodb,asndb,paths = geoasn.geoasn_load(dt, GEOASN_ROOT)
            #
            print >>sys.stderr, '   finished. done in %.1fs.' %(time.time()-stt )
        #
    else:
        form = ThisForm()

    return render_to_response('process_logs.html',  {'form': form, 'lst':lst, 'tsk':tsk},
            context_instance=RequestContext(request) )


def task_import_logs(dt):
    print >>sys.stderr, "   task_import_streams(%s) " %dt.date(),
    lst = []
    ok = zero = mal = 0
    dy = dt.day if dt>=datetime(2010,2,1) else dt.day+1
    files = enumerate_mlab_folder('%s/%4d/%02d/%02d' % (GLASNOST_ROOT, dt.year,dt.month, dy))
    for fl in files:
        ti = pre_parse_log(fl)
        if ti:
            gt = GlasTest.factory(ti)
            gt.save() # will raise on duplicate entries - so don't :-)
            ok += 1
        else:
            sz = os.path.getsize(fl)            
            if not sz:
                zero += 1
            else:
                lst.append(('! MALFORMED: %s'%fl, 'size: %dB'%sz ))
                mal += 1
        #
    #
    print >>sys.stderr, "   ... %d files,  %d imported, %d+%d malformed" %(len(files), ok, mal,zero)
    lst.append((dt, 'n: %d'%len(files)))
    return lst


def task_update_geoasn(dt,geodb,asndb,paths):
    print >>sys.stderr, "   task_update_geodb(%s)" %dt.date()
    tests = GlasTest.objects.filter( start_time__range=(dt,dt+timedelta(days=1,microseconds=-1)) )
    # loop over it, do following, save object
    for tst in tests:
        tst.cc = geodb.country_code_by_addr(tst.client_ip) or '--'
        tst.asn = asndb.Lookup(tst.client_ip) or 0
        tst.save()
    lst = [( dt, len(tests), '%s;%s'%(paths[0].replace('\\','/').split('/')[-1],paths[1].replace('\\','/').split('/')[-1]) )]
    return lst


def task_parse_analyze(dt):
    print >>sys.stderr, "   task_parse_analyze(%s)" %dt.date()
    tests = GlasTest.objects.filter( start_time__range=(dt,dt+timedelta(days=1,microseconds=-1)) ).filter( skip_this=False )
    stat = {'DPI':0,'UNDEF':0,'OK':0,'PORT':0,'OK1/2':0}
    skipv1,skipv2 = 0,0

    for t in tests:
        if t.proto=='BitTorrent (v1-log)':
            # get measurements for version 1 log
            assert datetime(2009,01,01)<=dt<=datetime(2010,04,20)
            try:
                fl = get_log_name(GLASNOST_ROOT, t.start_time, t.client_ip, t.mlab_server)
                measurements, ti = parse_log_oldstyle1(fl)
            except Exception as ex:
                if str(ex) not in ('bad header','corrupt log','negative client speed') and 'bad flow count' not in str(ex):
                    print >>sys.stderr, "   ! parse_log1() ex: '%s' @%d (#%d)" % (ex, sys.exc_info()[2].tb_next.tb_lineno, t.id)
                skipv1 += 1
                continue
        elif t.proto:
            # get measurements for version 2 log
            assert dt>=datetime(2010,04,20)
            try:
                measurements, ti = parse_summary_string_log2(t.client_sum,t.server_sum)
            except Exception as ex:
                print >>sys.stderr, "   ! parse_log2() ex: '%s' @%d (#%d)" % (ex, sys.exc_info()[2].tb_next.tb_lineno, t.id)
                skipv2 += 1
                continue
        else:
            print >>sys.stderr, "   ! skipped, no protocol (#%d)" % t.id
        #

        try:
            r,rw,ri = glasnost_analysis_v2(measurements)
            stat[r['verdict']] += 1
        except Exception as ex:
            print >>sys.stderr, "   ! analysis2() ex: %s @%d (#%d)" % (ex, sys.exc_info()[2].tb_next.tb_lineno, t.id)
            continue

        # store in model
        t_v = GlasVerdict.factory(t,ti,r,rw)
        t_vi = GlasVerdict_i.factory(t,ri)
        t_v.save()  # also will raise exception if duplicate. so comment/uncomment when testing :-)
        t_vi.save()

    if tests:
        n = len(tests) - skipv1
        of, df, pf, hf, uf = (stat['OK']*100./n, stat['DPI']*100./n, stat['PORT']*100./n,stat['OK1/2']*100./n,stat['UNDEF']*100./n) if n!=0 else (0,0,0,0,0)
        lst = [(dt,len(tests),"%s/%s"%(skipv1,skipv2),round(of),round(df),round(pf),round(hf),round(uf))]
        print >>sys.stderr, "   => tests,skipv1/2,OK,DPI,PORT,OK1/2,UNDEF=" + str(lst) #
    else:
        lst = [(dt,len(tests))]
        print >>sys.stderr
    return lst


def enumerate_mlab_folder(fdir):
    filelist = []
    if os.path.isdir(fdir):
        for ls in os.listdir(fdir):
            assert re.match(r'mlab[0-9]\.(\S+)\.measurement-lab\.org', ls)
            ll = os.listdir('%s/%s' % (fdir, ls) )
            for l in ll:
                if not l.endswith('.log') and not l.endswith('.log.gz'):
                    continue
                assert re.match(r'([0-9-]+)T([0-9:_]{8})_([0-9.]+)_([0-9a-zA-Z._\-]+)\.log', l)
                thefile = '%s/%s/%s' % (fdir, ls, l)
                filelist.append(thefile)
    return filelist

