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
import six


from manila.common import constants as const
from manila import context
from manila import exception
from manila.share import configuration
from manila.share.drivers.inspur.as13000 import as13000_nas
from manila.tests import fake_share
from manila import test


CONF = cfg.CONF


test_config = configuration.Configuration(None)
test_config.as13000_nas_ip = 'some_ip'
test_config.as13000_nas_port = 'as13000_api_port'
test_config.as13000_nas_login = 'username'
test_config.as13000_nas_password = 'password'
test_config.inspur_as13000_share_pool = 'fake_pool'


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
        #mock_rt = self.mock_object(self.rest_api, 'refresh_token', mock.Mock())
        self.assertRaises(
            exception.ShareBackendException,
            self.rest_api.send_rest_api,
            method='fake_method',
            params='fake_params',
            request_type='fake_type')
        mock_sa.assert_called_with('fake_method',
                                   'fake_params',
                                   'fake_type')
        # mock_rt.assert_called_with(force=True)

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
        self.assertRaises(exception.ShareBackendException, self.as13000_driver.do_setup,self._ctxt)
        mock_login.assert_called_once()

    def test_do_setup_vpe_failed(self):
        mock_login = self.mock_object(
            as13000_nas.RestAPIExecutor, 'logins', mock.Mock())
        mock_vpe = self.mock_object(
            self.as13000_driver,
            '_validate_pools_exist',
            mock.Mock(side_effect= exception.InvalidInput(reason='fake_exception')))
        self.assertRaises(exception.InvalidInput, self.as13000_driver.do_setup, self._ctxt)
        mock_login.assert_called_once()
        mock_vpe.assert_called_once()

    # def test_check_for_setup_error(self):
    #     self.as13000_driver.storage_pool = 'fake_pool'
    #     self.as13000_driver.ips = ['fake_ip']
    #     self.as13000_driver.check_for_setup_error()

    # def test_check_for_setup_error_fail1(self):
    #     self.as13000_driver.storage_pool = 'fake_pool'
    #     self.as13000_driver.ips = ['fake_ip']
    #     self.as13000_driver.check_for_setup_error()

    def test_create_share(self):
        pass
