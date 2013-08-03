# Glasnost Parser v2.
# Developed 2011/2012 by Hadi Asghari (http://deeppacket.info)

from django.conf.urls import patterns, url

urlpatterns = patterns('parser.views',
    url(r'^/do$','ProcessLogs', name='main_process_logs'),
)

  