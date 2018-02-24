# Copyright 2018 Inspur Corp.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Share driver test for Inspur AS13000
"""

import ddt
import json
import mock
from oslo_config import cfg
import requests


from manila import context
from manila import exception
from manila.share import configuration
from manila.share.drivers.inspur.as13000 import as13000_nas
from manila.tests import fake_share
from manila import test
from manila.share import utils as share_utils

CONF = cfg.CONF


test_config = configuration.Configuration(None)
test_config.as13000_nas_ip = 'some_ip'
test_config.as13000_nas_port = 'as13000_api_port'
test_config.as13000_nas_login = 'username'
test_config.as13000_nas_password = 'password'
test_config.inspur_as13000_share_pool = 'fakepool'
test_config.directory_protection_info = {'type': 0,
                                         "dc": 2,
                                         "cc": 1,
                                         "rn": 0,
                                         "st": 4}


class FakeResponse(object):
    def __init__(self, status, output):
        self.status_code = status
        self.text = 'return message'
        self._json = output

    def json(self):
        return self._json

    def close(self):
        pass


@ddt.ddt
class RestAPIExecutorTestCase(test.TestCase):
    def setUp(self):
        self.rest_api = as13000_nas.RestAPIExecutor(
            test_config.as13000_nas_ip,
            test_config.as13000_nas_port,
            test_config.as13000_nas_login,
            test_config.as13000_nas_password)
        super(RestAPIExecutorTestCase, self).setUp()

    def test_logins(self):
        mock_login = self.mock_object(self.rest_api, 'login',
                                      mock.Mock(return_value='fake_token'))
        self.rest_api.logins()
        mock_login.assert_called_once()

    def test_login(self):
        fake_response = {
            'token': 'fake_token',
            'expireTime': '7200',
            'type': 0}
        mock_sra = self.mock_object(self.rest_api, 'send_rest_api',
                                    mock.Mock(return_value=fake_response))
        result = self.rest_api.login()

        self.assertEquals('fake_token', result)

        login_params = {'name': test_config.as13000_nas_login,
                        'password': test_config.as13000_nas_password}
        mock_sra.assert_called_once_with(method='security/token',
                                         params=login_params,
                                         request_type='post')

    def test_logout(self):
        mock_sra = self.mock_object(self.rest_api, 'send_rest_api',
                                    mock.Mock(return_value=None))
        self.rest_api.logout()
        mock_sra.assert_called_once_with(
            method='security/token', request_type='delete')

    @ddt.data(True, False)
    def test_refresh_token(self, force):
        mock_login = self.mock_object(self.rest_api, 'login',
                                      mock.Mock(return_value='fake_token'))
        mock_logout = self.mock_object(self.rest_api, 'logout',
                                       mock.Mock())
        self.rest_api.refresh_token(force)
        if force is not True:
            mock_logout.assert_called_once_with()
        mock_login.assert_called_once_with()

    def test_send_rest_api(self):
        expected = {'value': 'abc'}
        mock_sa = self.mock_object(self.rest_api, 'send_api',
                                   mock.Mock(return_value=expected))
        result = self.rest_api.send_rest_api(
            method='fake_method',
            params='fake_params',
            request_type='fake_type')
        self.assertEquals(expected, result)
        mock_sa.assert_called_once_with(
            'fake_method',
            'fake_params',
            'fake_type')

    def test_send_rest_api_retry(self):
        expected = {'value': 'abc'}
        mock_sa = self.mock_object(
            self.rest_api,
            'send_api',
            mock.Mock(
                side_effect=(
                    exception.NetworkException,
                    expected)))
        # mock.Mock(side_effect=exception.NetworkException))
        mock_rt = self.mock_object(self.rest_api, 'refresh_token', mock.Mock())
        result = self.rest_api.send_rest_api(
            method='fake_method',
            params='fake_params',
            request_type='fake_type'
        )
        self.assertEquals(expected, result)
        mock_sa.assert_called_with(
            'fake_method',
            'fake_params',
            'fake_type')
        mock_rt.assert_called_with(force=True)

    def test_send_rest_api_3times_fail(self):
        mock_sa = self.mock_object(
            self.rest_api, 'send_api', mock.Mock(
                side_effect=(exception.NetworkException)))
        mock_rt = self.mock_object(self.rest_api, 'refresh_token', mock.Mock())
        self.assertRaises(
            exception.ShareBackendException,
            self.rest_api.send_rest_api,
            method='fake_method',
            params='fake_params',
            request_type='fake_type')
        mock_sa.assert_called_with('fake_method',
                                   'fake_params',
                                   'fake_type')
        mock_rt.assert_called_with(force=True)

    def test_send_rest_api_backend_error_fail(self):
        mock_sa = self.mock_object(self.rest_api, 'send_api', mock.Mock(
            side_effect=(exception.ShareBackendException('fake_error_message'))))
        mock_rt = self.mock_object(self.rest_api, 'refresh_token')
        self.assertRaises(
            exception.ShareBackendException,
            self.rest_api.send_rest_api,
            method='fake_method',
            params='fake_params',
            request_type='fake_type')
        mock_sa.assert_called_with('fake_method',
                                   'fake_params',
                                   'fake_type')
        mock_rt.assert_not_called()

    @ddt.data(
        {'method': 'fake_method', 'request_type': 'post', 'params':
            {'fake_param': 'fake_value'}},
        {'method': 'fake_method', 'request_type': 'get', 'params':
            {'fake_param': 'fake_value'}},
        {'method': 'fake_method', 'request_type': 'delete', 'params':
            {'fake_param': 'fake_value'}},
        {'method': 'fake_method', 'request_type': 'put', 'params':
            {'fake_param': 'fake_value'}}, )
    @ddt.unpack
    def test_send_api(self, method, params, request_type):
        self.rest_api._token_pool = ['fake_token']
        if request_type in ('post', 'delete', 'put'):
            fake_output = {'code': 0, 'message': 'success'}
        elif request_type == 'get':
            fake_output = {'code': 0, 'data': 'fake_date'}
        mock_request = self.mock_object(
            requests, request_type, mock.Mock(
                return_value=FakeResponse(
                    200, fake_output)))
        self.rest_api.send_api(
            method,
            params=params,
            request_type=request_type)
        mock_request.assert_called_once_with(
            'http://%s:%s/rest/%s' %
            (test_config.as13000_nas_ip,
             test_config.as13000_nas_port,
             method),
            data=json.dumps(params),
            headers={'X-Auth-Token': 'fake_token'})

    @ddt.data({'method': r'security/token',
               'params': {'name': test_config.as13000_nas_login,
                          'password': test_config.as13000_nas_password},
               'request_type': 'post'},
              {'method': r'security/token',
               'params': '',
               'request_type': 'delete'})
    @ddt.unpack
    def test_send_api_access_success(self, method, params, request_type):
        if request_type == 'post':
            fake_value = {'code': 0, 'data': {
                'token': 'fake_token',
                'expireTime': '7200',
                'type': 0}}
            mock_requests = self.mock_object(
                requests, 'post', mock.Mock(
                    return_value=FakeResponse(
                        200, fake_value)))
            result = self.rest_api.send_api(method, params, request_type)
            self.assertEqual(fake_value['data'], result)
            mock_requests.assert_called_once_with(
                'http://%s:%s/rest/%s' %
                (test_config.as13000_nas_ip,
                 test_config.as13000_nas_port,
                 method),
                data=json.dumps(params),
                headers=None)
        if request_type == 'delete':
            fake_value = {'code': 0, 'message': 'Success!'}
            self.rest_api._token_pool = ['fake_token']
            mock_requests = self.mock_object(
                requests, 'delete', mock.Mock(
                    return_value=FakeResponse(
                        200, fake_value)))
            self.rest_api.send_api(method, params, request_type)
            mock_requests.assert_called_once_with(
                'http://%s:%s/rest/%s' %
                (test_config.as13000_nas_ip,
                 test_config.as13000_nas_port,
                 method),
                data=json.dumps(''),
                headers={'X-Auth-Token': 'fake_token'})

    def test_send_api_wrong_access_fail(self):
        req_params = {'method': r'security/token',
                      'params': {'name': test_config.as13000_nas_login,
                                 'password': 'fake_password'},
                      'request_type': 'post'}
        fake_value = {'message': ' User name or password error.', 'code': 400}
        mock_request = self.mock_object(
            requests, 'post', mock.Mock(
                return_value=FakeResponse(
                    200, fake_value)))
        self.assertRaises(
            exception.ShareBackendException,
            self.rest_api.send_api,
            method=req_params['method'],
            params=req_params['params'],
            request_type=req_params['request_type'])
        mock_request.assert_called_once_with(
            'http://%s:%s/rest/%s' %
            (test_config.as13000_nas_ip,
             test_config.as13000_nas_port,
             req_params['method']),
            data=json.dumps(
                req_params['params']),
            headers=None)

    def test_send_api_token_overtime_fail(self):
        self.rest_api._token_pool = ['fake_token']
        fake_value = {'method': 'fake_url',
                      'params': 'fake_params',
                      'reuest_type': 'post'}
        fake_out_put = {'message': 'Unauthorized access!', 'code': 301}
        mock_requests = self.mock_object(
            requests, 'post', mock.Mock(
                return_value=FakeResponse(
                    200, fake_out_put)))
        self.assertRaises(exception.NetworkException,
                          self.rest_api.send_api,
                          method='fake_url',
                          params='fake_params',
                          request_type='post')
        mock_requests.assert_called_once_with(
            'http://%s:%s/rest/%s' %
            (test_config.as13000_nas_ip,
             test_config.as13000_nas_port,
             fake_value['method']),
            data=json.dumps('fake_params'),
            headers={
                'X-Auth-Token': 'fake_token'})

    def test_send_api_fail(self):
        self.rest_api._token_pool = ['fake_token']
        fake_output = {'code': 'fake_code', 'message': 'fake_message'}
        mock_request = self.mock_object(
            requests, 'post', mock.Mock(
                return_value=FakeResponse(
                    200, fake_output)))
       # self.rest_api.send_api()
        self.assertRaises(
            exception.ShareBackendException,
            self.rest_api.send_api,
            method='fake_method',
            params='fake_params',
            request_type='post')
        mock_request.assert_called_once_with(
            'http://%s:%s/rest/%s' %
            (test_config.as13000_nas_ip,
             test_config.as13000_nas_port,
             'fake_method'),
            data=json.dumps('fake_params'),
            headers={'X-Auth-Token': 'fake_token'}
        )


@ddt.ddt
class AS13000ShareDriverTestCase(test.TestCase):
    def __init__(self, *args, **kwds):
        super(AS13000ShareDriverTestCase, self).__init__(*args, **kwds)
        self._ctxt = context.get_admin_context()
        self.configuration = test_config

    def setUp(self):
        CONF.set_default('driver_handles_share_servers', False)
        self.rest_api = as13000_nas.RestAPIExecutor(
            test_config.as13000_nas_ip,
            test_config.as13000_nas_port,
            test_config.as13000_nas_login,
            test_config.as13000_nas_password)
        self.as13000_driver = as13000_nas.AS13000ShareDriver(
            configuration=self.configuration)
        super(AS13000ShareDriverTestCase, self).setUp()

    def test_do_setup(self):
        mock_login = self.mock_object(
            as13000_nas.RestAPIExecutor, 'logins', mock.Mock())
        mock_vpe = self.mock_object(
            self.as13000_driver,
            '_validate_pools_exist',
            mock.Mock())
        mock_sp = self.mock_object(
            self.as13000_driver, '_get_storage_pool', mock.Mock(
                return_value='fake_storage_pool'))
        mock_gni = self.mock_object(
            self.as13000_driver, '_get_nodes_ips', mock.Mock(
                return_value=['fake_ips']))
        self.as13000_driver.do_setup(self._ctxt)
        mock_login.assert_called_once()
        mock_vpe.assert_called_once()
        mock_sp.assert_called_once_with(
            test_config.inspur_as13000_share_pool[0])
        mock_gni.assert_called_once()

    def test_do_setup_login_fail(self):
        mock_login = self.mock_object(
            as13000_nas.RestAPIExecutor, 'logins', mock.Mock(
                side_effect=exception.ShareBackendException('fake_exception')))
        self.assertRaises(
            exception.ShareBackendException,
            self.as13000_driver.do_setup,
            self._ctxt)
        mock_login.assert_called_once()

    def test_do_setup_vpe_failed(self):
        mock_login = self.mock_object(
            as13000_nas.RestAPIExecutor, 'logins', mock.Mock())
        mock_vpe = self.mock_object(
            self.as13000_driver, '_validate_pools_exist', mock.Mock(
                side_effect=exception.InvalidInput(
                    reason='fake_exception')))
        self.assertRaises(
            exception.InvalidInput,
            self.as13000_driver.do_setup,
            self._ctxt)
        mock_login.assert_called_once()
        mock_vpe.assert_called_once()

    # def test_check_for_setup_error(self):
    #     self.as13000_driver.storage_pool = 'fakepool'
    #     self.as13000_driver.ips = ['fake_ip']
    #     self.as13000_driver.check_for_setup_error()

    # def test_check_for_setup_error_fail1(self):
    #     self.as13000_driver.storage_pool = 'fakepool'
    #     self.as13000_driver.ips = ['fake_ip']
    #     self.as13000_driver.check_for_setup_error()

    @ddt.data(fake_share.fake_share(share_proto='nfs'),
              fake_share.fake_share(share_proto='cifs'))
    def test_create_share(self, share):
        mock_gsp = self.mock_object(
            self.as13000_driver,
            '_get_share_pnsp',
            mock.Mock(
                return_value=(
                    'fakepool',
                    share['name'],
                    share['size'],
                    share['share_proto'])))
        mock_cd = self.mock_object(self.as13000_driver, '_create_directory',
                                   mock.Mock(return_value='fakepath'))
        mock_cns = self.mock_object(self.as13000_driver, '_create_nfs_share')
        mock_ccs = self.mock_object(self.as13000_driver, '_create_cifs_share')
        mock_sdq = self.mock_object(
            self.as13000_driver,
            '_set_directory_quota')
        mock_glp = self.mock_object(
            self.as13000_driver, '_get_location_path', mock.Mock(
                return_value='fake_location_path'))
        location_path_expect = self.as13000_driver.create_share(
            self._ctxt, share)
        self.assertEqual('fake_location_path', location_path_expect)
        mock_gsp.assert_called_once_with(share)
        mock_cd.assert_called_once_with(
            share_name='fakename', pool_name='fakepool')
        if share['share_proto'] is 'nfs':
            mock_cns.assert_called_once_with(share_path='fakepath')
        elif share['share_proto'] is 'cifs':
            mock_ccs.assert_called_once_with(
                share_path='fakepath', share_name='fakename')
        mock_sdq.assert_called_once_with('fakepath', share['size'])
        mock_glp.assert_called_once_with(
            share['name'], 'fakepath', share['share_proto'])

    def test_create_share_fail(self):
        share = fake_share.fake_share()
        mock_gsp = self.mock_object(self.as13000_driver, '_get_share_pnsp',
                                    mock.Mock(
                                        return_value=(
                                            'fakepool',
                                            share['name'],
                                            share['size'],
                                            share['share_proto'])))
        mock_cd = self.mock_object(self.as13000_driver, '_create_directory',
                                   mock.Mock(return_value='fakepath'))
        self.assertRaises(
            exception.InvalidInput,
            self.as13000_driver.create_share,
            self._ctxt,
            share)
        mock_gsp.assert_called_once_with(share)
        mock_cd.assert_called_once_with(
            share_name='fakename', pool_name='fakepool')

    @ddt.data(fake_share.fake_share(share_proto='nfs'),
              fake_share.fake_share(share_proto='cifs'))
    def test_create_share_from_snapshot(self, share):
        fake_snapshot = fake_share.fake_snapshot(create_instance=True)
        mock_gsp = self.mock_object(
            self.as13000_driver,
            '_get_share_pnsp',
            mock.Mock(
                return_value=(
                    'fakepool',
                    share['name'],
                    share['size'],
                    share['share_proto'])))
        mock_cd = self.mock_object(self.as13000_driver, '_create_directory',
                                   mock.Mock(return_value='fakepath'))
        mock_cdtd = self.mock_object(
            self.as13000_driver,
            '_clone_directory_to_dest')
        mock_cns = self.mock_object(self.as13000_driver, '_create_nfs_share')
        mock_ccs = self.mock_object(self.as13000_driver, '_create_cifs_share')
        mock_sdq = self.mock_object(
            self.as13000_driver,
            '_set_directory_quota')
        mock_glp = self.mock_object(
            self.as13000_driver, '_get_location_path', mock.Mock(
                return_value='fake_location_path'))
        location_path_expect = self.as13000_driver.create_share_from_snapshot(
            self._ctxt, share, fake_snapshot)
        self.assertEqual('fake_location_path', location_path_expect)
        mock_gsp.assert_called_once_with(share)
        mock_cd.assert_called_once_with(
            share_name='fakename', pool_name='fakepool')
        mock_cdtd.assert_called_once_with(
            snapshot=fake_snapshot, dest_path='fakepath')
        if share['share_proto'] is 'nfs':
            mock_cns.assert_called_once_with(share_path='fakepath')
        elif share['share_proto'] is 'cifs':
            mock_ccs.assert_called_once_with(
                share_path='fakepath', share_name='fakename')
        mock_sdq.assert_called_once_with('fakepath', share['size'])
        mock_glp.assert_called_once_with(
            share['name'], 'fakepath', share['share_proto'])

    def test_create_share_from_snapshot_fail(self):
        share = fake_share.fake_share()
        snapshot = fake_share.fake_snapshot(create_instance=True)
        mock_gsp = self.mock_object(self.as13000_driver, '_get_share_pnsp',
                                    mock.Mock(
                                        return_value=(
                                            'fakepool',
                                            share['name'],
                                            share['size'],
                                            share['share_proto'])))
        mock_cd = self.mock_object(self.as13000_driver, '_create_directory',
                                   mock.Mock(return_value='fakepath'))
        mock_cdtd = self.mock_object(
            self.as13000_driver,
            '_clone_directory_to_dest')
        self.assertRaises(
            exception.InvalidInput,
            self.as13000_driver.create_share_from_snapshot,
            self._ctxt,
            share, snapshot)
        mock_gsp.assert_called_once_with(share)
        mock_cd.assert_called_once_with(
            share_name='fakename', pool_name='fakepool')
        mock_cdtd.assert_called_once_with(
            snapshot=snapshot, dest_path='fakepath')

    @ddt.data(fake_share.fake_share(share_proto='nfs'),
              fake_share.fake_share(share_proto='cifs'))
    def test_delete_share(self, share):
        mock_gsp = self.mock_object(self.as13000_driver, '_get_share_pnsp',
                                    mock.Mock(
                                        return_value=(
                                            'fakepool',
                                            share['name'],
                                            share['size'],
                                            share['share_proto'])))
        fake_path = r'/%s/%s' % ('fakepool', share['name'])
        mock_gns = self.mock_object(
            self.as13000_driver, '_get_nfs_share', mock.Mock(
                return_value=['fake_share']))
        mock_dns = self.mock_object(self.as13000_driver, '_delete_nfs_share')
        mock_gcs = self.mock_object(
            self.as13000_driver, '_get_cifs_share', mock.Mock(
                return_value=['fake_share']))
        mock_dcs = self.mock_object(self.as13000_driver, '_delete_cifs_share')
        mock_dd = self.mock_object(self.as13000_driver, '_delete_directory')
        self.as13000_driver.delete_share(self._ctxt, share)
        mock_gsp.assert_called_once_with(share)
        if share['share_proto'] is 'nfs':
            mock_gns.assert_called_once_with(fake_path)
            mock_dns.assert_called_once_with(fake_path)

        elif share['share_proto'] is 'cifs':
            mock_gcs.assert_called_once_with(share['name'])
            mock_dcs.assert_called_once_with(share['name'])
        mock_dd.assert_called_once_with(fake_path)

    @ddt.data(fake_share.fake_share(share_proto='nfs'),
              fake_share.fake_share(share_proto='cifs'))
    def test_delete_share_not_exist(self, share):
        mock_gsp = self.mock_object(self.as13000_driver, '_get_share_pnsp',
                                    mock.Mock(
                                        return_value=(
                                            'fakepool',
                                            share['name'],
                                            share['size'],
                                            share['share_proto'])))
        fake_path = r'/%s/%s' % ('fakepool', share['name'])
        mock_gns = self.mock_object(
            self.as13000_driver,
            '_get_nfs_share',
            mock.Mock(
                return_value=[]))
        mock_gcs = self.mock_object(
            self.as13000_driver,
            '_get_cifs_share',
            mock.Mock(
                return_value=[]))
        self.as13000_driver.delete_share(self._ctxt, share)
        mock_gsp.assert_called_once_with(share)
        if share['share_proto'] is 'nfs':
            mock_gns.assert_called_once_with(fake_path)

        elif share['share_proto'] is 'cifs':
            mock_gcs.assert_called_once_with(share['name'])

    def test_delete_share_fail(self):
        share = fake_share.fake_share()
        mock_gsp = self.mock_object(self.as13000_driver, '_get_share_pnsp',
                                    mock.Mock(
                                        return_value=(
                                            'fakepool',
                                            share['name'],
                                            share['size'],
                                            share['share_proto'])))
        self.assertRaises(
            exception.InvalidInput,
            self.as13000_driver.delete_share,
            self._ctxt,
            share,)
        mock_gsp.assert_called_once_with(share)

    def test_extend_share(self):
        share = fake_share.fake_share()
        mock_gsp = self.mock_object(self.as13000_driver, '_get_share_pnsp',
                                    mock.Mock(
                                        return_value=(
                                            'fakepool',
                                            share['name'],
                                            share['size'],
                                            share['share_proto'])))
        share_path = r'/%s/%s' % ('fakepool', share['name'])
        mock_sdq = self.mock_object(
            self.as13000_driver,
            '_set_directory_quota')
        self.as13000_driver.extend_share(share, 2)
        mock_gsp.assert_called_once_with(share)
        mock_sdq.assert_called_once_with(share_path, 2)

    def test_shrink_share(self):
        share = fake_share.fake_share(size=20)
        new_size = 15
        mock_gsp = self.mock_object(self.as13000_driver, '_get_share_pnsp',
                                    mock.Mock(
                                        return_value=(
                                            'fakepool',
                                            share['name'],
                                            share['size'],
                                            share['share_proto'])))
        share_path = r'/%s/%s' % ('fakepool', share['name'])
        mock_gdq = self.mock_object(self.as13000_driver,
                                    '_get_directory_quata',
                                    mock.Mock(return_value=(20, 5)))
        mock_sdq = self.mock_object(self.as13000_driver,
                                    '_set_directory_quota')
        self.as13000_driver.shrink_share(share, new_size)
        mock_gsp.assert_called_once_with(share)
        mock_gdq.assert_called_once_with(share_path)
        mock_sdq.assert_called_once_with(share_path, new_size)

    def test_shrink_share_fail(self):
        share = fake_share.fake_share(size=20)
        new_size = 10
        mock_gsp = self.mock_object(self.as13000_driver, '_get_share_pnsp',
                                    mock.Mock(
                                        return_value=(
                                            'fakepool',
                                            share['name'],
                                            share['size'],
                                            share['share_proto'])))
        share_path = r'/%s/%s' % ('fakepool', share['name'])
        mock_gdq = self.mock_object(
            self.as13000_driver,
            '_get_directory_quata',
            mock.Mock(
                return_value=(20, 15)))
        self.assertRaises(
            exception.ShareShrinkingError,
            self.as13000_driver.shrink_share,
            share,
            new_size)
        mock_gsp.assert_called_once_with(share)
        mock_gdq.assert_called_once_with(share_path)

    @ddt.data(fake_share.fake_share(share_proto='nfs'),
              fake_share.fake_share(share_proto='cifs'))
    def test_ensure_share(self, share):
        mock_gsp = self.mock_object(self.as13000_driver, '_get_share_pnsp',
                                    mock.Mock(
                                        return_value=(
                                            'fakepool',
                                            share['name'],
                                            share['size'],
                                            share['share_proto'])))
        fake_path = r'/%s/%s' % ('fakepool', share['name'])
        mock_gns = self.mock_object(
            self.as13000_driver, '_get_nfs_share', mock.Mock(
                return_value=['fake_share']))
        mock_gcs = self.mock_object(
            self.as13000_driver, '_get_cifs_share', mock.Mock(
                return_value=['fake_share']))
        mock_glp = self.mock_object(
            self.as13000_driver, '_get_location_path', mock.Mock(
                return_value='fake_location_path'))
        expect_location = 'fake_location_path'
        location_path = self.as13000_driver.ensure_share(self._ctxt, share)
        self.assertEqual(expect_location, location_path)
        mock_gsp.assert_called_once_with(share)
        if share['share_proto'] is 'nfs':
            mock_gns.assert_called_once_with(fake_path)

        elif share['share_proto'] is 'cifs':
            mock_gcs.assert_called_once_with(share['name'])
        mock_glp.assert_called_once_with(
            share['name'], fake_path, share['share_proto'])

    def test_ensure_share_fail_1(self):
        share = fake_share.fake_share()
        mock_gsp = self.mock_object(self.as13000_driver, '_get_share_pnsp',
                                    mock.Mock(
                                        return_value=(
                                            'fakepool',
                                            share['name'],
                                            share['size'],
                                            share['share_proto'])))
        self.assertRaises(
            exception.InvalidInput,
            self.as13000_driver.ensure_share,
            self._ctxt,
            share)
        mock_gsp.assert_called_once_with(share)

    @ddt.data(fake_share.fake_share(share_proto='nfs'),
              fake_share.fake_share(share_proto='cifs'))
    def test_ensure_share_None_share_fail(self, share):
        mock_gsp = self.mock_object(self.as13000_driver, '_get_share_pnsp',
                                    mock.Mock(
                                        return_value=(
                                            'fakepool',
                                            share['name'],
                                            share['size'],
                                            share['share_proto'])))
        fake_path = r'/%s/%s' % ('fakepool', share['name'])
        mock_gns = self.mock_object(
            self.as13000_driver, '_get_nfs_share', mock.Mock(
                return_value=[]))
        mock_gcs = self.mock_object(
            self.as13000_driver, '_get_cifs_share', mock.Mock(
                return_value=[]))
        self.assertRaises(
            exception.ShareResourceNotFound,
            self.as13000_driver.ensure_share,
            self._ctxt,
            share)
        mock_gsp.assert_called_once_with(share)
        if share['share_proto'] is 'nfs':
            mock_gns.assert_called_once_with(fake_path)
        elif share['share_proto'] is 'cifs':
            mock_gcs.assert_called_once_with(share['name'])

    def test_create_snapshot(self):
        share_in_snapshot = fake_share.fake_share()
        fake_snapshot = fake_share.fake_snapshot(
            create_instance=True, share=share_in_snapshot)
        share = fake_snapshot['share']
        mock_gsp = self.mock_object(self.as13000_driver, '_get_share_pnsp',
                                    mock.Mock(
                                        return_value=(
                                            'fakepool',
                                            share['name'],
                                            share['size'],
                                            share['share_proto'])))
        fake_path = r'/%s/%s' % ('fakepool', share['name'])
        mock_fn = self.mock_object(self.as13000_driver, '_format_name',
                                   mock.Mock(return_value='formatname'))
        mock_rest = self.mock_object(
            as13000_nas.RestAPIExecutor, 'send_rest_api')
        self.as13000_driver.create_snapshot(self._ctxt, fake_snapshot)
        mock_gsp.assert_called_once_with(share)
        mock_fn.assert_called_once_with('snap_%s' % fake_snapshot['id'])
        method = 'snapshot/directory'
        request_type = 'post'
        params = {'path': fake_path, 'snapName': 'formatname'}
        mock_rest.assert_called_once_with(
            method=method, request_type=request_type, params=params)

    def test_delete_snapshot_normal(self):
        share_in_snapshot = fake_share.fake_share()
        fake_snapshot = fake_share.fake_snapshot(
            create_instance=True, share=share_in_snapshot)
        share = fake_snapshot['share']
        mock_gsp = self.mock_object(self.as13000_driver, '_get_share_pnsp',
                                    mock.Mock(return_value=(
                                        'fakepool',
                                        share['name'],
                                        share['size'],
                                        share['share_proto'])))
        fake_path = r'/%s/%s' % ('fakepool', share['name'])
        mock_gsfs = self.mock_object(self.as13000_driver,
                                     '_get_snapshots_from_share',
                                     mock.Mock(return_value=['fakesnapshot']))
        mock_fn = self.mock_object(self.as13000_driver, '_format_name',
                                   mock.Mock(return_value='formatname'))
        mock_rest = self.mock_object(
            as13000_nas.RestAPIExecutor, 'send_rest_api')
        self.as13000_driver.delete_snapshot(self._ctxt, fake_snapshot)
        mock_gsp.assert_called_once_with(share)
        mock_fn.assert_called_once_with('snap_%s' % fake_snapshot['id'])
        mock_gsfs.assert_called_once_with(fake_path)
        method = 'snapshot/directory?path=%s&snapName=%s' % (
                 fake_path, 'formatname')
        request_type = 'delete'
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type)

    def test_delete_snapshot_not_exist(self):
        share_in_snapshot = fake_share.fake_share()
        fake_snapshot = fake_share.fake_snapshot(
            create_instance=True, share=share_in_snapshot)
        share = fake_snapshot['share']
        mock_gsp = self.mock_object(self.as13000_driver, '_get_share_pnsp',
                                    mock.Mock(return_value=(
                                        'fakepool',
                                        share['name'],
                                        share['size'],
                                        share['share_proto'])))
        fake_path = r'/%s/%s' % ('fakepool', share['name'])
        mock_gsfs = self.mock_object(self.as13000_driver,
                                     '_get_snapshots_from_share',
                                     mock.Mock(return_value=[]))
        self.as13000_driver.delete_snapshot(self._ctxt, fake_snapshot)
        mock_gsp.assert_called_once_with(share)
        mock_gsfs.assert_called_once_with(fake_path)

    @ddt.data(fake_share.fake_share(share_proto='nfs'),
              fake_share.fake_share(share_proto='cifs'))
    def test_update_access(self, share):
        access_rules = [{'access_to': 'fakename1',
                         'access_level': 'fakelevel1'},
                        {'access_to': 'fakename2',
                         'access_level': 'fakelevel2'}]
        add_rules = []
        delete_rules = []
        mock_ca = self.mock_object(self.as13000_driver, '_clear_access')
        mock_gsp = self.mock_object(self.as13000_driver, '_get_share_pnsp',
                                    mock.Mock(return_value=(
                                        'fakepool',
                                        share['name'],
                                        share['size'],
                                        share['share_proto'])))
        fake_path = r'/%s/%s' % ('fakepool', share['name'])
        fake_share_backend = {
            'name': share['name'],
            'pathAuthority': 'fakepathAuthority'}
        mock_gns = self.mock_object(
            self.as13000_driver, '_get_nfs_share', mock.Mock(
                return_value=fake_share_backend))
        mock_rest = self.mock_object(
            as13000_nas.RestAPIExecutor, 'send_rest_api')
        self.as13000_driver.update_access(
            self._ctxt, share, access_rules, add_rules, delete_rules)
        mock_ca.assert_called_once_with(share)
        mock_gsp.assert_called_once_with(share)
        if share['share_proto'] is 'nfs':
            client_type = 0
        elif share['share_proto'] is 'cifs':
            client_type = 1
        access_clients = []
        for access in access_rules:
            access_to = access['access_to']
            access_level = access['access_level']
            client = {'name': access_to,
                      'type': client_type,
                      'authority': access_level}
            access_clients.append(client)
        params = {'addedClientList': access_clients,
                  'deletedClientList': [],
                  'editedClientList': []}
        if share['share_proto'] is 'nfs':
            mock_gns.assert_called_once_with(fake_path)
            params['path'] = fake_path
            params['pathAuthority'] = fake_share_backend['pathAuthority']
        elif share['share_proto'] is 'cifs':
            params['path'] = fake_path
            params['name'] = share['name']
        mock_rest.assert_called_once_with(
            method=('file/share/%s' % share['share_proto']),
            params=params,
            request_type='put')

    @ddt.data(fake_share.fake_share(share_proto='nfs'),
              fake_share.fake_share(share_proto='cifs'))
    def test__clear_access(self, share):
        mock_gsp = self.mock_object(self.as13000_driver, '_get_share_pnsp',
                                    mock.Mock(return_value=(
                                        'fakepool',
                                        share['name'],
                                        share['size'],
                                        share['share_proto'])))
        fake_path = r'/%s/%s' % ('fakepool', share['name'])
        fake_share_backend = {'name': share['name'],
                              'pathAuthority': 'fakepathAuthority',
                              'clientList': ['fakeclient'],
                              'userList': ['fakeuser']}
        mock_gns = self.mock_object(self.as13000_driver, '_get_nfs_share',
                                    mock.Mock(return_value=fake_share_backend))
        mock_gcs = self.mock_object(self.as13000_driver, '_get_cifs_share',
                                    mock.Mock(return_value=fake_share_backend))
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')
        self.as13000_driver._clear_access(share)
        mock_gsp.assert_called_once_with(share)
        proto = share['share_proto']
        method = 'file/share/%s' % proto
        request_type = 'put'
        params = {}
        if proto is 'nfs':
            mock_gns.assert_called_once_with(fake_path)
            client_list = fake_share_backend['clientList']
            params['path'] = fake_path
            params['pathAuthority'] = fake_share_backend['pathAuthority']
        elif proto is 'cifs':
            mock_gcs.assert_called_once_with(share['name'])
            client_list = fake_share_backend['userList']
            params['path'] = fake_path
            params['name'] = share['name']
        params.update({'addedClientList': [],
                       'deletedClientList': client_list,
                       'editedClientList': []})
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type,
                                          params=params)

    def test__validate_pools_exist(self):
        self.as13000_driver.pools = ['fakepool']
        mock_gdl = self.mock_object(self.as13000_driver, '_get_directory_list',
                                    mock.Mock(return_value=['fakepool']))
        self.as13000_driver._validate_pools_exist()
        mock_gdl.assert_called_once_with('/')

    def test__validate_pools_exist_fail(self):
        self.as13000_driver.pools = ['fakepool_fail']
        mock_gdl = self.mock_object(self.as13000_driver, '_get_directory_list',
                                    mock.Mock(return_value=['fakepool']))
        self.assertRaises(exception.InvalidInput,
                          self.as13000_driver._validate_pools_exist)
        mock_gdl.assert_called_once_with('/')

    def test__get_directory_quata(self):
        fake_data = {'hardthreshold': 200,
                     'hardunit': 0,
                     'capacity': '50GB'}
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock(return_value=fake_data))
        mock_uc = self.mock_object(self.as13000_driver,
                                   '_unit_convert',
                                   mock.Mock(return_value=50))
        expected = (200, 50)
        total_capacity, used_capacity = self.as13000_driver._get_directory_quata(
            'fakepath')
        self.assertEqual(expected, (total_capacity, used_capacity))
        method = 'file/quota/directory?path=/%s' % 'fakepath'
        request_type = 'get'
        mock_rest.assert_called_once_with(
            method=method, request_type=request_type)
        mock_uc.assert_called_once_with('50GB')

    def test__get_directory_quata_fail(self):
        fake_data = {'hardthreshold': None,
                     'hardunit': 0,
                     'capacity': '50GB'}
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock(return_value=fake_data))
        self.assertRaises(exception.ShareBackendException,
                          self.as13000_driver._get_directory_quata, 'fakepath')
        method = 'file/quota/directory?path=/%s' % 'fakepath'
        request_type = 'get'
        mock_rest.assert_called_once_with(
            method=method, request_type=request_type)

    def test__get_pools_stats(self):
        mock_gdq = self.mock_object(
            self.as13000_driver,
            '_get_directory_quata',
            mock.Mock(
                return_value=(
                    200,
                    50)))
        pool = {}
        pool['pool_name'] = 'fakepath'
        pool['reserved_percentage'] = 0
        pool['max_over_subscription_ratio'] = 20.0
        pool['dedupe'] = False
        pool['compression'] = False
        pool['qos'] = False
        pool['thin_provisioning'] = True
        pool['total_capacity_gb'] = 200
        pool['free_capacity_gb'] = 150
        pool['allocated_capacity_gb'] = 50
        pool['snapshot_support'] = True
        pool['create_share_from_snapshot_support'] = True
        result = self.as13000_driver._get_pools_stats('fakepath')
        self.assertEqual(pool, result)
        mock_gdq.assert_called_once_with('fakepath')

    def test__get_directory_list(self):
        fake_directory_list = [{'name': 'fakedirectory1', 'size': 20}, {
            'name': 'fakedirectory2', 'size': 30}]
        mock_rest = self.mock_object(
            as13000_nas.RestAPIExecutor, 'send_rest_api', mock.Mock(
                return_value=fake_directory_list))
        expected = ['fakedirectory1', 'fakedirectory2']
        result = self.as13000_driver._get_directory_list('fakepath')
        self.assertEqual(expected, result)
        mock_rest.assert_called_once_with(
            method=(
                'file/directory?path=%s' %
                'fakepath'),
            request_type='get')

    @ddt.data({'type': 0, "dc": 2, "cc": 1, "rn": 0, "st": 3},
              {'type': 1, 'strategy': 2})
    def test__create_directory(self, fake_protection):
        self.as13000_driver.configuration.directory_protection_info = \
            fake_protection
        self.as13000_driver.storage_pool = 'fakepool'
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')
        fake_share_name = 'fakename'
        fake_pool_name = 'fakepool'
        expect = r'/%s/%s' % (fake_pool_name, fake_share_name)
        result = self.as13000_driver._create_directory(
            fake_share_name, fake_pool_name)
        self.assertEqual(expect, result)
        authority_info = {"user": "root",
                          "group": "root",
                          "authority": "rwxrwxrwx"}
        method = 'file/directory'
        request_type = 'post'
        params = {'name': fake_share_name,
                  'parentPath': '/%s' % fake_pool_name,
                  'authorityInfo': authority_info,
                  'dataProtection': fake_protection,
                  'poolName': 'fakepool'}
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type,
                                          params=params)

    @ddt.data(None,
              {'type': 0, "dc": 2, "cc": 1, "rn": 0, "st_fail": 3},
              {'type': 1, 'strategy_fail': 2},
              {'type': 1, 'strategy': 5})
    def test__create_directory_fail(self, fake_protection):
        self.as13000_driver.configuration.directory_protection_info = \
            fake_protection
        self.as13000_driver.storage_pool = 'fakepool'
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')
        fake_share_name = 'fakename'
        fake_pool_name = 'fakepool'
        if fake_protection is None:
            self.assertRaises(exception.ShareBackendException,
                              self.as13000_driver._create_directory,
                              fake_share_name, fake_pool_name)
            mock_rest.assert_not_called()
        else:
            self.assertRaises(exception.InvalidInput,
                              self.as13000_driver._create_directory,
                              fake_share_name, fake_pool_name)
            mock_rest.assert_not_called()

    def test__delete_directory(self):
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')
        self.as13000_driver._delete_directory('fakepath')
        method = 'file/directory?path=%s' % 'fakepath'
        request_type = 'delete'
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type)

    def test__set_directory_quota(self):
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')
        self.as13000_driver._set_directory_quota('fakepath', 'fakesize')
        method = 'file/quota/directory'
        request_type = 'put'
        params = {'path': 'fakepath',
                  'hardthreshold': 'fakesize',
                  'hardunit': 2}
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type,
                                          params=params)

    def test__create_nfs_share(self):
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')
        self.as13000_driver._create_nfs_share('fakepath')
        method = 'file/share/nfs'
        request_type = 'post'
        params = {'path': 'fakepath', 'pathAuthority': 'rw', 'client': []}
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type,
                                          params=params)

    def test__delete_nfs_share(self):
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')
        self.as13000_driver._delete_nfs_share('fakepath')
        method = 'file/share/nfs?path=%s' % 'fakepath'
        request_type = 'delete'
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type)

    def test__get_nfs_share(self):
        mock_rest = self.mock_object(
            as13000_nas.RestAPIExecutor, 'send_rest_api', mock.Mock(
                return_value='fakesharebackend'))
        expect = 'fakesharebackend'
        result = self.as13000_driver._get_nfs_share('fakepath')
        self.assertEqual(expect, result)
        method = 'file/share/nfs?path=%s' % 'fakepath'
        request_type = 'get'
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type)

    def test__create_cifs_share(self):
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')
        self.as13000_driver._create_cifs_share('fakename', 'fakepath')
        method = 'file/share/cifs'
        request_type = 'post'
        params = {'path': 'fakepath', 'name': 'fakename', 'userlist': []}
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type,
                                          params=params)

    def test__delete_cifs_share(self):
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')
        self.as13000_driver._delete_cifs_share('fakename')
        method = 'file/share/cifs?name=%s' % 'fakename'
        request_type = 'delete'
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type)

    def test__get_cifs_share(self):
        mock_rest = self.mock_object(
            as13000_nas.RestAPIExecutor, 'send_rest_api', mock.Mock(
                return_value='fakesharebackend'))
        expect = 'fakesharebackend'
        result = self.as13000_driver._get_cifs_share('fakename')
        self.assertEqual(expect, result)
        method = 'file/share/cifs?name=%s' % 'fakename'
        request_type = 'get'
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type)

    def test__clone_directory_to_dest(self):
        shares = fake_share.fake_share(host='fakehost')
        fake_snapshot = {'share_id': 'fakeshareid',
                         'snapshot_id': 'fakesnapshotid',
                         'share_instance': shares}
        mock_util = self.mock_object(share_utils, 'extract_host',
                                     mock.Mock(return_value='fakepool'))
        mock_fn = self.mock_object(
            self.as13000_driver,
            '_format_name',
            mock.Mock(
                side_effect=(
                    'share_fakeshareid',
                    'snap_fakesnapshotid')))
        mock_rest = self.mock_object(
            as13000_nas.RestAPIExecutor, 'send_rest_api')
        self.as13000_driver._clone_directory_to_dest(fake_snapshot, 'fakepath')
        mock_util.assert_called_once_with(shares['host'], level='pool')
        mock_fn.assert_called()
        method = 'snapshot/directory/clone'
        request_type = 'post'
        params = {'path': '/%s/%s' % ('fakepool', 'share_fakeshareid'),
                  'snapName': 'snap_%s' % fake_snapshot['snapshot_id'],
                  'destPath': 'fakepath'}
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type,
                                          params=params)

    def test__get_snapshots_from_share(self):
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock(return_value='fakesnap'))
        result = self.as13000_driver._get_snapshots_from_share('fakepath')
        self.assertEqual('fakesnap', result)
        method = 'snapshot/directory?path=%s' % 'fakepath'
        request_type = 'get'
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type)

    @ddt.data('nfs', 'cifs')
    def test__get_location_path(self, proto):
        self.as13000_driver.ips = ['ip1', 'ip2']
        if proto is 'nfs':
            expect = [{'path': r'%(ips)s:%(share_phth)s'
                               % {'ips': ip, 'share_phth': 'fakepool'}}
                      for ip in ['ip1', 'ip2']]
        elif proto is 'cifs':
            expect = [{'path': r'\\%(ips)s\%(share_name)s'
                               % {'ips': ip,
                                  'share_name': 'fakeshare'}}
                      for ip in ['ip1', 'ip2']]

        result = self.as13000_driver._get_location_path('fakeshare',
                                                        'fakepool',
                                                        proto)
        self.assertEqual(expect, result)

    def test__get_nodes_ips(self):
        cluster = [{'ip': 'fakeip1', 'runningStatus': 1, 'healthStatus': 1},
                   {'ip': 'fakeip2', 'runningStatus': 1, 'healthStatus': 1},
                   {'ip': 'fakeip3', 'runningStatus': 1, 'healthStatus': 1}]
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock(return_value=cluster))
        expect = ['fakeip1', 'fakeip2', 'fakeip3']
        result = self.as13000_driver._get_nodes_ips()
        self.assertEqual(expect, result)
        mock_rest.assert_called_once_with(method='cluster/node',
                                          request_type='get')

    def test__get_share_pnsp(self):
        share = fake_share.fake_share(host='fakehost')
        mock_utils = self.mock_object(share_utils, 'extract_host',
                                      mock.Mock(return_value='fakepool'))
        mock_fn = self.mock_object(self.as13000_driver, '_format_name',
                                   mock.Mock(return_value='share_fakeid'))
        expect = ('fakepool', 'share_fakeid', 1, 'fake_proto')
        result = self.as13000_driver._get_share_pnsp(share)
        self.assertEqual(expect, result)
        mock_utils.assert_called_once_with('fakehost', level='pool')
        mock_fn.assert_called_once_with('share_%s' % share['id'])

    @ddt.data('50000000', '500000k', '50mb', '50G', '50TB')
    def test__unit_convert(self, capacity):
        trans = {'50000000': (50000000 / 1024**3),
                 '500000k': 500000 / (1024**2),
                 '50mb': 50 / 1024,
                 '50G': 50,
                 '50TB': 50 * 1024}
        expect = trans[capacity]
        result = self.as13000_driver._unit_convert(capacity)
        self.assertEqual(expect, result)

    def test__format_name(self):
        a = 'atest-1234567890-1234567890-1234567890'
        expect = 'atest_1234567890_1234567890_12'
        result = self.as13000_driver._format_name(a)
        self.assertEqual(expect, result)

    def test__get_storage_pool(self):
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock(return_value=[{'poolName': 'fakepool'}]))
        result = self.as13000_driver._get_storage_pool('fakepath')
        self.assertEqual('fakepool', result)
        method = 'file/directory/detail?path=/%s' % 'fakepath'
        request_type = 'get'
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type)
