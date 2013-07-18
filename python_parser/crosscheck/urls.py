from django.conf.urls import patterns, url

urlpatterns = patterns('crosscheck.views',
    url(r'^/do$','RunScript', name='crosscheck_run'),
)

  