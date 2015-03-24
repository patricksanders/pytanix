import json
import os
import requests
from pprint import pprint

docs_url = 'https://10.10.46.30:9440/PrismGateway/services/rest/api/api-docs/v1/'
os.environ['no_proxy'] = '10.10.46.30'
base = requests.get(docs_url, verify=False)
base = json.loads(base.text)
for api in base['apis']:
    path = api['path']
    name = path.lstrip('/')
    url = docs_url + name
    r = requests.get(url, verify=False)
    with open(os.path.join('json', name + '.json'), 'w') as f:
        f.write(r.text)
