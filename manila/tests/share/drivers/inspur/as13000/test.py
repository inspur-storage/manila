import requests
import json

if __name__ == '__main__':
    url = 'http://10.180.210.15:8088/rest/security/token'
    params = {'name': 'ro1ot', 'password': 'passw0rd'}
    params = json.dumps(params)
    rt = 'post'

    req = requests.post(url=url, data=params)
   #  req = requests.delete(url=url, headers={'X-Auth-Token': 'q97i9b25r9pvtnsnfkt2p3a0o5'})
    print req.status_code
    print req.json()
    # print '\n'.join(['%s:%s' % item for item in req.__dict__.item()])