from django.conf.urls import patterns, url

urlpatterns = patterns('parser.views',
    url(r'^/do$','ProcessLogs', name='main_process_logs'),
)

  