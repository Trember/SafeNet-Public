import datetime
class ServerConsts():
    (HOST , PORT) = ("0.0.0.0", 8069)

class SafeBrowsingConsts():
    API_KEY = "Safe Browsing API Key"
    DATABAS_DIR = "mongodb directory"
    THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING" , "UNWANTED_SOFTWARE"] #["MALWARE", "SOCIAL_ENGINEERING" , "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION" ]
    HOST = "safebrowsing.googleapis.com"
    PORT = 443  # HTTPS uses port 443

class HostNamesDBConsts():
    HOST = "data.iana.org"
    PORT = 80 # HTTPS uses port 443
    MINIMUM_WAIT_DURATION = 1 #1 day
    SECONDS_IN_A_DAY = 86400
     