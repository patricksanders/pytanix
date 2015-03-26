import pytanix
import base64
import os
import config

ip = config.PRISM_IP
user = config.USERNAME
password = config.PASSWORD

# Don't use a proxy
os.environ['no_proxy'] = ip

# Configure basic auth
creds = user + ':' + password
auth = base64.b64encode(creds)

nutanix = pytanix.Nutanix(ip, auth=auth)
nutanix.trace = True
nutanix.verify_ssl = False
#nutanix.add_ntp_server("10.10.46.1")
nutanix.get_ntp_servers()
nutanix.get_ntp_servers()

