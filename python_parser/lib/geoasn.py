# functions to load GeoIP & AsnDB files

#todo: move to its own folder. django didn't recognize paths, so got to find out why and how to fix

import os
import PyASN
import platform
import datetime

def geoasn_load(dt, root):
    """Loads the nearest possible GeoDB & AsnDB files to the given data and return as tuple"""
    # 1. find nearest existing
    dtu = dt
    while dtu > dt-datetime.timedelta(days=10):
        files = geoasn_exists(dtu, root)
        if files:
            break
        dtu -= datetime.timedelta(days = 1)
    if not files:
        raise Exception('Geo & ASN files for %s not found' % dt)
    # 2. load & return
    geodb_file, asndb_file = files
    asndb = PyASN.new( asndb_file  )
    if platform.system() == "Linux":
        import GeoIP
        geodb = GeoIP.open( geodb_file, GeoIP.GEOIP_MEMORY_CACHE)
    else:
        import pygeoip
        geodb = pygeoip.GeoIP( geodb_file, pygeoip.MEMORY_CACHE)
    return geodb,asndb, (geodb_file,asndb_file)


def geoasn_exists(dt, root):
    """Checks whether a Geo & Asn DBs exists for a particular day. Returns the filenames as a tuple if they exist"""
    geodb_file = root + '/db.geoip/GeoIP-106_%4d%02d%02d.dat' % (dt.year, dt.month, dt.day)
    if not os.path.exists(geodb_file):
        return None
    asndb_file = root + '/db.rviews/ipasn_%4d%02d%02d.dat' % (dt.year, dt.month, dt.day)
    if not os.path.exists(asndb_file):
        return None
    return geodb_file,asndb_file

  