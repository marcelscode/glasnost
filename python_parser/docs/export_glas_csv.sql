select t.id,t.start_time,t.client_ip,t.mlab_server,t.cc,t.asn,t.num_flows,proto,
runtime, max_up,max_dn,appdiff_up,appdiff_dn, portdiff_up,
portdiff_dn, failedv_up, failedv_dn, has_forgrst, verdict, undef_reason,
w_btfaster, w_strangediff, w_cfnpfail, w_fail2x, w_broken,w_portchange,iu_failed,id_failed,
iu_ad1,iu_ad2,iu_pd1,iu_pd2,id_ad1,id_ad2,id_pd1,
id_pd2,i_btafaster,i_btpfaster,i_strangedif1,i_strangedif2,
  INTO OUTFILE '/tmp/csv2.csv'
  FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '"'
  LINES TERMINATED BY '\n'
from glasnost_glastest as t
join glasnost_verdict as v on t.id=v.test_id
join glasnost_verdict_i as vi on t.id=vi.test_id
order by start_time

