#xss_security_gui/utils/disable_ssl_warnings.py
import urllib3

def disable_ssl_warnings():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)