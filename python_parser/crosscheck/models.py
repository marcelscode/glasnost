from datetime import datetime
from django.db import models
from parser.models import GlasTest


class Detection_Result(models.Model):
    test          = models.OneToOneField(GlasTest)
    up_app_diff   = models.CharField(max_length=5,blank=True,default='')  # upload-app-differentiation: ok, throt, noise
    up_port_diff  = models.CharField(max_length=5,blank=True,default='')  # upload-port-differentiation: ok, throt, noise
    dn_app_diff   = models.CharField(max_length=5,blank=True,default='')
    dn_port_diff  = models.CharField(max_length=5,blank=True,default='')
    up_failed     = models.TextField(blank=True,default='')               # upload-flows-failed or blocked. (currently unimplemented!?)
    dn_failed     = models.TextField(blank=True,default='')
    error         = models.TextField(blank=True,default='')
    script_output = models.TextField()
    created       = models.DateTimeField(default=datetime.now())
    #
