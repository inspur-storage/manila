import requests
import json
from oslo_log import log as logging

def login():
    url = 'http://10.180.210.15:8088/rest/security/token'
    params = {'name': 'root', 'password': 'passw0rd'}
    params = json.dumps(params)
    rt = 'post'

    req = requests.post(url=url, data=params)
    req = req.json()
    print req
    return req['data']['token']
if __name__ == '__main__':
    LOG = logging.getLogger(__name__)
    LOG.debug('test%s,%s',['a','b'])


    #tetset