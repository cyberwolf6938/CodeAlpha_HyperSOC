# hypersensor/geoip.py

geo_cache = {}

def get_country(ip):

    if ip in geo_cache:
        return geo_cache[ip]

    # Local networks

    if (
        ip.startswith("192.168.")
        or ip.startswith("10.")
        or ip.startswith("127.")
    ):
        country = "LOCAL"

    else:
        country = "Unknown"

    geo_cache[ip] = country

    return country