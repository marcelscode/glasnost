from datetime import timedelta, datetime
from django.db import transaction
from django.forms import forms, fields
from django.shortcuts import render_to_response
from django.template.context import RequestContext
import time
from parser.models import GlasTest
import sys
from mpiWrapper import mpiWrapper


def RunScript(request):
    lst1,lst2,tsk = [], [], None
    class ThisForm(forms.Form):
        start_date = fields.DateField(initial='2010-05-01')
        end_date   = fields.DateField(initial='2010-05-01')

    if request.method == 'POST':
        form = ThisForm(request.POST)
        if form.is_valid():
            dt0, end = form.cleaned_data['start_date'], form.cleaned_data['end_date']
            dt = datetime(dt0.year,dt0.month,dt0.day)
            end = datetime(end.year,end.month,end.day)
            stt = time.time()
            while dt <= end:
                with transaction.commit_manually():
                    try:
                        l1,l2 = perl_glasnost_differentiation_detector(dt)
                        lst1 += l1
                        lst2 += l2
                        dt += timedelta(days = 1)
                    except Exception as ex:
                        transaction.rollback()
                        raise ex,None,sys.exc_traceback
                    else:
                        transaction.commit()
            #
        print >>sys.stderr, '   request done in %.1fs.' %(time.time()-stt)
    else:
        form = ThisForm()

    return render_to_response('mpi_run.html',  {'form': form,'lst1':lst1,'lst2':lst2}, context_instance=RequestContext(request) )





def perl_glasnost_differentiation_detector(dt):
    print >>sys.stderr, "   perl_glasnost_differentiation_detector(%s)" %dt
    l1,l2 = [],[]
    tests = GlasTest.objects.filter( start_time__range=(dt,dt+timedelta(days=1,microseconds=-1)) ).filter( skip_this=False )
    mpiobj = mpiWrapper()
    for test in tests:
        mpi_result = mpiobj.analyze(test)
        #l1.append(mpi_result) #DBG
        mpi_result.save()
    #
    mpiobj.close()
    l2.append((dt,len(tests)))
    return l1,l2



	

def task_analysis2_vs_mpi(dt):
    # TODO: 1. ADD A VIEW FOR THIS -  (and link the parser page to it too)
    # TODO: 2. WHY NO OUTPUT? -> it expects a J object which we are not using; not sure where that code is from

    print >>sys.stderr, "   task_analysis2_vs_mpi(%s)" %dt.date(),
    tests = GlasTest.objects.filter( start_time__range=(dt,dt+timedelta(days=1,microseconds=-1)) ).filter( skip_this=False ).exclude( proto='BitTorrent (v1-log)')
    # note: excluding comparison with BitTorrent (v1-log) for now, as the mpi tester can't do them
    mpiobj = mpiWrapper()
    noteq, noteqfail, notbt, wfaster, wport, wbrok = 0, 0, 0, 0, 0, 0

    for t in tests:
        mp = mpiobj.analyze(t)
        try:
            streams, ti= parse_summary_string_log2(t.client_sum,t.server_sum)
            r,w,i = glasnost_analysis_v2(streams)
        except:
            print>> sys.stderr, "    cannot parse/analyze #%d - skip" % t.id
            continue
        comp = compare_mpi_with_us2(mp,r,w,i)
        if comp=='notbt': notbt += 1
        elif comp=='wbroken': wbrok += 1
        elif comp=='wfaster': wfaster += 1
        elif comp=='wportch': wport += 1
        elif comp=='noteqfail2': noteqfail += 1
        elif comp=='noteq': noteq += 1
        elif comp=='ok': pass
        else: raise Exception('unexpected result %s'%comp)

    mpiobj.close()
    print >>sys.stderr, "   ...... tests=%4d, noteq=%d+%d, wfast/wport=%2d+%2d, brokdo/notbtdo=%2d+%2d" %(len(tests),noteq, noteqfail, wfaster, wport, wbrok, notbt)
    lst = [(len(tests),noteq, noteqfail, wfaster, wport, wbrok, notbt)]  # ?
    return lst


def compare_mpi_with_us2(mp,r,w,i):
    if mp.error and 'unsupported' in mp.error:
        return 'notbt'
    elif mp.error:
        assert mp.error=='Missing bandwidth measurement'
        assert (w['w_broken'] and r['verdict'] in ('DPI','PORT')) or ['w_portchange']
        return 'wbroken'
    else:
        diffsnoeq = r['u_app_diff']!=mp.up_app_diff or r['d_app_diff']!=mp.dn_app_diff or\
                    r['u_port_diff']!=mp.up_port_diff or r['d_port_diff']!=mp.dn_port_diff
        failednoeq = set(re.sub('#[0-9]r[0-9]','',i['iu_failed']).split('(')) != set(mp.up_failed.replace('failed','').split('(')) or\
                     set(re.sub('#[0-9]r[0-9]','',i['id_failed']).split('(')) != set(mp.dn_failed.replace('failed','').split('('))
        if diffsnoeq or failednoeq:
            if w['w_btfaster']:
                return 'wfaster'
            elif w['w_portchange']:
                return 'wportch'
            elif diffsnoeq and ('has_fail2' in r and r['has_fail2']):
                return 'noteqfail2'
            else:
                # this should rarely occur!
                # for debug: tmp = glasnost_analysis_v2(streams)
                return 'noteq'
        #
        return 'ok'
    #endif


	