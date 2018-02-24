import requests
import json


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
    # url = 'http://10.180.210.15:8088/rest/file/directory/detail?path=/atest'
    # req = requests.get(url=url, headers={'X-Auth-Token': login()})
    # # print req.status_code
    # print req.json()
    # print '\n'.join(['%s:%s' % item for item in req.__dict__.item()])
    ips = ['a','b']
    location = [
        {'path': r'%(ips)s:%(share_phth)s'
                 % {'ips': ip, 'share_phth': 'fake'}
         }
        for ip in ips
    ]
    print location