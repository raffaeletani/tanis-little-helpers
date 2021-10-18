'''
Since we use certbot to issue ssl certificates, with each renewal, we have to update the ssl thumbprint in the emby ldap plugin.
this script does this automatically. call it after the certbot renew command finished
'''
import requests
from OpenSSL.crypto import load_certificate, FILETYPE_PEM

apiUrl = 'https://yourembyinstallation/emby/'
apiKey = '123456789yourembyapikey'
apiHeaders = {'X-Emby-Token' : apiKey, 'accept' : 'application/json'}
apiHeadersPost = {'X-Emby-Token' : apiKey, 'accept' : '*/*', 'Content-Type' : 'application/octet-stream'}
pluginName = 'LDAP'
pathToCert = 'abs-path-to/cert.pem'
pluginId = None
pluginConfig = None
newhash = None

# 1. get plugin id 

r1 =requests.get(apiUrl + 'Plugins', headers=apiHeaders)
for plugin in r1.json():
    if plugin['Name'] == pluginName:
        pluginId = plugin['Id']

# 2. get old plugin config

if pluginId is not None:
    r2 =requests.get(apiUrl + 'Plugins/' + pluginId + '/Configuration', headers=apiHeaders)
    pluginConfig = r2.json()

# 3. get new hash
if pluginConfig is not None:
    cert_file_string = open(pathToCert, "rb").read()
    cert = load_certificate(FILETYPE_PEM, cert_file_string)
    sha1_fingerprint = cert.digest("sha1").decode('utf8').replace(':','')
    newhash = sha1_fingerprint


# 4. replace new hash in config and post it to server
if newhash is not None:
    pluginConfig['CertHash'] = newhash
    r3 =requests.post(apiUrl + 'Plugins/' + pluginId + '/Configuration',json = pluginConfig, headers=apiHeadersPost)
    print(r3.status_code)
    print(r3.text)
