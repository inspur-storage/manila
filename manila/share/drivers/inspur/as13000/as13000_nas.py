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
Share driver for Inspur AS13000
"""

import functools
import json
import re
import requests
import time

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import units
from manila import exception
from manila.share import driver
from manila.share import utils as share_utils


LOG = logging.getLogger(__name__)

inspur_as13000_opts = [
    cfg.HostAddressOpt('as13000_nas_ip',
                       help='As13000 IP address.'),
    cfg.IntOpt('as13000_api_port',
               default=8088,
               help='The port that Driver used to send request to the backend.'),
    cfg.StrOpt('as13000_nas_login',
               help='as13000_nas_username'),
    cfg.StrOpt('as13000_nas_password',
               help='as13000_nas_password'),
    cfg.ListOpt('inspur_as13000_share_pool',
                default=['Pool0'],
                help='The Storage Pool Manila use.'),
    cfg.IntOpt('as13000_token_available_time',
               default=3600,
               help='The valid period of token.'),
    cfg.DictOpt('directory_protection_info',
                default={'type': 0,
                         "dc": 2, "cc": 1, "rn": 0, "st": 4},
                help='The protection info of directory.')
]

CONF = cfg.CONF
CONF.register_opts(inspur_as13000_opts)


def inspur_driver_debug_trace(f):
    """Log the method entrance and exit including active backend name.
    This should only be used on VolumeDriver class methods. It depends on
    having a 'self' argument that is a AS13000_Driver.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        driver = args[0]
        cls_name = driver.__class__.__name__
        method_name = "%(cls_name)s.%(method)s" % {"cls_name": cls_name,
                                                   "method": f.__name__}
        # backend_name = driver._update_volume_stats.get('volume_backend_name')
        backend_name = driver.configuration.share_backend_name
        LOG.debug("[%(backend_name)s] Enter %(method_name)s" %
                  {"method_name": method_name, "backend_name": backend_name})
        result = f(*args, **kwargs)
        LOG.debug("[%(backend_name)s] Leave %(method_name)s" %
                  {"method_name": method_name, "backend_name": backend_name})
        return result

    return wrapper


class RestAPIExecutor(object):
    def __init__(self, hostname, port, username, password):
        self._hostname = hostname
        self._port = port
        self._username = username
        self._password = password
        self._token_pool = []
        self._token_size = 1

    def logins(self):
        """login the AS13000 and store the token in token_pool"""
        times = self._token_size
        while times > 0:
            token = self.login()
            self._token_pool.append(token)
            times = times - 1
        LOG.debug('Login the AS13000.')

    def login(self):
        """login in the AS13000 and return the token"""
        method = 'security/token'
        params = {'name': self._username, 'password': self._password}
        token = self.send_rest_api(method=method, params=params,
                                   request_type='post').get('token')
        return token

    def logout(self):
        method = 'security/token'
        self.send_rest_api(method=method, request_type='delete')

    def refresh_token(self, force=False):
        if force is True:
            for i in range(self._token_size):
                self._token_pool = []
                token = self.login()
                self._token_pool.append(token)
        else:
            for i in range(self._token_size):
                self.logout()
                token = self.login()
                self._token_pool.append(token)
        LOG.debug('Tokens have been refreshed.')

    def send_rest_api(self, method, params=None, request_type='post'):
        attempts = 3
        while attempts > 0:
            attempts -= 1
            try:
                return self.send_api(method, params, request_type)
            except exception.NetworkException,e:
                LOG.error(e)
                msge = str(e)
                self.refresh_token(force=True)
                time.sleep(1)
            except exception.ShareBackendException,e:
                msge = str(e)
                break
        msg = r'Error running RestAPI : /rest/%s ; Error Message: %s' %(method,msge)
        LOG.error(msg)
        raise exception.ShareBackendException(msg)

    def send_api(self, method, params=None, request_type='post'):
        if params is not None:
            params = json.dumps(params)
        url = 'http://%s:%s/%s/%s' % (self._hostname, self._port, 'rest',
                                      method)
        # https = {'method': request_type,
        #          'utl': url,
        #          'params': params}
        # print https
        # header is not needed when the driver login the backend
        if method == 'security/token':
            # token won't be return to the token_pool
            if request_type == 'delete':
                header = {'X-Auth-Token': self._token_pool.pop(0)}
            else:
                header = None
        else:
            if len(self._token_pool) == 0:
                self.logins()
            token = self._token_pool.pop(0)
            header = {'X-Auth-Token': token}
            self._token_pool.append(token)

        if request_type == 'post':

            req = requests.post(url,
                                data=params,
                                headers=header)
        elif request_type == 'get':
            req = requests.get(url,
                               data=params,
                               headers=header)
        elif request_type == 'put':
            req = requests.put(url,
                               data=params,
                               headers=header)
        elif request_type == 'delete':
            req = requests.delete(url,
                                  data=params,
                                  headers=header)
        else:
            msg = 'Unsupported request_type: %s' % request_type
            raise exception.ShareBackendException(msg)

        if req.status_code != 200:
            msg = 'Error code: %s , API: %s , Message: %s' % (req.status_code, req.url, req.text)
            LOG.error(msg)
            raise exception.NetworkException(msg)
        try:
            response = req.json()
            code = response.get('code')
            if code == 0:
                if request_type == 'get':
                    data = response.get('data')

                else:
                    if method == 'security/token':
                        data = response.get('data')
                    else:
                        data = response.get('message')
                        data = str(data).lower()
                        if hasattr(data, 'success'):
                            return
            elif code == 301:
                msg = 'Token is out time'
                LOG.error(msg)
                raise exception.NetworkException(msg)
            else:
                message = response.get('message') # response['message']
                msg = ('The RestAPI exception output:'
                       'Message:%s, Code:%s' % (message, code))
                LOG.error(msg)
                raise exception.ShareBackendException(msg)

        except ValueError:
            raise exception.ShareBackendException(msg)
            data = None

        req.close()

        return data


class AS13000ShareDriver(driver.ShareDriver):
    """ AS13000 Share Driver

        Version history:
        V1.0.0:    Initial version
        V1.1.0:    fix location problem and extend unit_convert
                   provide more exception info
        """

    VENDOR = 'INSPUR'
    VERSION = '1.1.0'
    PROTOCOL = 'NFS_CIFS'


    def __init__(self, *args, **kwargs):
        super(AS13000ShareDriver, self).__init__(False, *args, **kwargs)
        self.configuration.append_config_values(inspur_as13000_opts)
        self.hostname = self.configuration.as13000_nas_ip
        self.port = self.configuration.as13000_api_port
        self.username = self.configuration.as13000_nas_login
        self.password = self.configuration.as13000_nas_password
        self.token_available_time = (self.configuration.
                                     as13000_token_available_time)
        self.storage_pool = None
        self.pools = ''
        self._token_time = 0
        self.ips = []
        self._rest = None


    @inspur_driver_debug_trace
    def do_setup(self, context):
        # get the RestAPIExecutor
        self._rest = RestAPIExecutor(self.hostname, self.port,
                                     self.username, self.password)
        # get tokens for Driver
        self._rest.logins()
        self._token_time = time.time()

        # get pools names from configuration
        self.pools = self.configuration.inspur_as13000_share_pool

        # Check the pool in conf exist in the backend
        self._validate_pools_exist()

        # get directory
        self.storage_pool = self._get_storage_pool(self.pools[0])

        # get all backend node ip
        self.ips = self._get_nodes_ips()

    @inspur_driver_debug_trace
    def check_for_setup_error(self):
        # check the required flags in conf
        required_flags = ['as13000_nas_ip', 'as13000_nas_login', 'as13000_nas_password',
                          'inspur_as13000_share_pool', 'directory_protection_info']
        for flag in required_flags:
            if not self.configuration.safe_get(flag):
                msg = '%s is not set.' % flag
                LOG.error(msg)
                raise exception.InvalidInput(reason=msg)

    @inspur_driver_debug_trace
    def create_share(self, context, share, share_server=None):
        """Create a share."""
        pool, share_name, share_size, share_proto = self._get_share_pnsp(share)
        # dir_list = self._get_directory_list(pool)
        # if share_name in dir_list:
        #     msg = ('Share(%s) is exist in backend(%s) already.'
        #            % (share_name, share['host']))
        #     LOG.error(msg)
        #     raise exception.InvalidInput(msg)
        # 1.create directory first
        share_path = self._create_directory(share_name=share_name, pool_name=pool)
        # 2.create nfs/cifs share second
        if share_proto == 'nfs':
            self._create_nfs_share(share_path=share_path)
        elif share_proto == 'cifs':
            self._create_cifs_share(share_name=share_name,
                                    share_path=share_path)
        else:
            msg = 'Invalid NAS protocol supplied: %s.' % share_proto
            LOG.error(msg)
            raise exception.InvalidInput(msg)
        # 3.set the quota of directory
        self._set_directory_quota(share_path, share_size)

        locations = self._get_location_path(share_name, share_path, share_proto)
        LOG.debug('Create share: name:%s protocal:%s,location: %s'
                  % (share_name, share_proto, locations))
        return locations

    @inspur_driver_debug_trace
    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Create a share from snapshot."""
        pool, share_name, share_size, share_proto = self._get_share_pnsp(share)
        # dir_list = self._get_directory_list(pool)
        #
        # if share_name in dir_list:
        #     msg = ('Share(%s) is exist in backend(%s) already.'
        #            % (share_name, share['host']))
        #     LOG.error(msg)
        #     raise exception.InvalidInput(msg)
        # 1.create directory first
        share_path = self._create_directory(share_name=share_name,
                                            pool_name=pool)
        # 2.clone snapshot to dest_path
        self._clone_directory_to_dest(snapshot=snapshot, dest_path=share_path)
        # 3.create share
        if share_proto == 'nfs':
            self._create_nfs_share(share_path=share_path)
        elif share_proto == 'cifs':
            self._create_cifs_share(share_name=share_name,
                                    share_path=share_path)
        else:
            msg = 'Invalid NAS protocol supplied: %s.' % share_proto
            LOG.error(msg)
            raise exception.InvalidInput(msg)
        # 4.set the quota of directory
        self._set_directory_quota(share_path, share_size)

        locations = self._get_location_path(share_name, share_path, share_proto)
        LOG.debug('Create share from snapshot: name:%s protocal:%s,location: %s'
                  % (share_name, share_proto, locations))
        return locations

    @inspur_driver_debug_trace
    def delete_share(self, context, share, share_server=None):
        """Delete share."""
        pool, share_name, size, share_proto = self._get_share_pnsp(share)
        share_path = r'/%s/%s' % (pool, share_name)
        if share_proto == 'nfs':
            share_backend = self._get_nfs_share(share_path)
            if len(share_backend) == 0:
                return
            else:
                self._delete_nfs_share(share_path)
        elif share_proto == 'cifs':
            share_backend = self._get_cifs_share(share_name)
            if len(share_backend) == 0:
                return
            else:
                self._delete_cifs_share(share_name)
        else:
            msg = 'Invalid NAS protocol supplied: %s.' % share_proto
            LOG.error(msg)
            raise exception.InvalidInput(msg)
        self._delete_directory(share_path)
        LOG.debug('Delete share: name:%s' % share_name)

    @inspur_driver_debug_trace
    def extend_share(self, share, new_size, share_server=None):
        """extend share to new size"""
        pool, name, size, proto = self._get_share_pnsp(share)
        share_path = r'/%s/%s' % (pool, name)
        self._set_directory_quota(share_path, new_size)
        LOG.debug('extend share:%s to new size %s GB' % (name, new_size))

    @inspur_driver_debug_trace
    def shrink_share_police(self, share, new_size, share_server=None):
        """V1.0.1_217_JINAN_police shrink share to new size. Fake"""
        pool, name, size, proto = self._get_share_pnsp(share)
        share_path = r'/%s/%s' % (pool, name)
        self._set_directory_quota(share_path, new_size)
        LOG.debug('shrink share:%s to new size %s GB' % (name, new_size))

    @inspur_driver_debug_trace
    def shrink_share(self, share, new_size, share_server=None):
        """shrink share to new size. Before shrinking, Driver will make sure
        the new size is larger the share already used"""
        pool, name, size, proto = self._get_share_pnsp(share)
        share_path = r'/%s/%s' % (pool, name)
        current_quota, used_capacity = self._get_directory_quata(share_path)
        if new_size < used_capacity:
            msg = ('New size for shrink can not be less than used_capacity'
                   ' on array. (used_capacity: %s, new: %s)).'
                   % (used_capacity, new_size))
            LOG.error(msg)
            raise exception.ShareShrinkingError(reason=msg)
        self._set_directory_quota(share_path, new_size)
        LOG.debug('shrink share:%s to new size %s GB' % (name, new_size))

    @inspur_driver_debug_trace
    def ensure_share(self, context, share, share_server=None):
        """Ensure that share is exported."""
        pool, share_name, share_size, share_proto = self._get_share_pnsp(share)
        share_path = '/%s/%s' % (pool, share_name)
        if share_proto == 'nfs':
            share_backend = self._get_nfs_share(share_path)
        elif share_proto == 'cifs':
            share_backend = self._get_cifs_share(share_name)
        else:
            msg = 'Invalid NAS protocol supplied: %s.' % share_proto
            LOG.error(msg)
            raise exception.InvalidInput(msg)
        if len(share_backend) == 0:
            raise exception.ShareResourceNotFound(share_id=share['share_id'])
        else:
            location = self._get_location_path(share_name, share_path, share_proto)
            return location

    @inspur_driver_debug_trace
    def create_snapshot(self, context, snapshot, share_server=None):
        """create snapshot of share"""
        source_share = snapshot['share']
        pool, source_name, size, proto = self._get_share_pnsp(source_share)
        path = r'/%s/%s' % (pool, source_name)
        # format the name of snapshot
        snap_name = 'snap_%s' % snapshot['snapshot_id']
        snap_name = self._format_name(snap_name)
        method = 'snapshot/directory'
        request_type = 'post'
        params = {'path': path, 'snapName': snap_name}
        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)
        LOG.debug('Create snapshot %s of share %s' % (snap_name, source_name))

    @inspur_driver_debug_trace
    def delete_snapshot(self, context, snapshot, share_server=None):
        """delete snapshot of snapshot"""
        source_share = snapshot['share']
        pool, source_name, size, proto = self._get_share_pnsp(source_share)
        path = r'/%s/%s' % (pool, source_name)
        # if there no snaps in back,driver will do nothing but return
        snaps_backend = self._get_snapshots_from_share(path)
        if len(snaps_backend) == 0:
           return
        # format the name of snapshot
        snap_name = 'snap_%s' % snapshot['snapshot_id']
        snap_name = self._format_name(snap_name)
        method = 'snapshot/directory?path=%s&snapName=%s' % (path, snap_name)
        request_type = 'delete'
        self._rest.send_rest_api(method=method, request_type=request_type)
        LOG.debug('Delete snapshot %s of share %s' % (snap_name, source_name))

    @inspur_driver_debug_trace
    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):# Todo
        """update access of share"""
        self._clear_access(share)
        pool, share_name, size, proto = self._get_share_pnsp(share)
        share_path = r'/%s/%s' % (pool, share_name)

        access_clients = []
        if proto == 'nfs':
            client_type = 0
        if proto == 'cifs':
            client_type = 1
        for access in access_rules:
            access_to = access['access_to']
            access_level = access['access_level']
            client = {'name': access_to, 'type': client_type, 'authority': access_level}
            access_clients.append(client)
        method = 'file/share/%s' % proto
        request_type = 'put'
        params = {'addedClientList': access_clients,
                  'deletedClientList': [],
                  'editedClientList': []}
        if proto == 'nfs':
            share_backend = self._get_nfs_share(share_path)
            params['path'] = share_path
            params['pathAuthority'] = share_backend['pathAuthority']
        elif proto == 'cifs':
            params['path'] = share_path
            params['name'] = share_name
        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)
        LOG.debug('Update access of share name:%s, accesses:%s'
                  % (share['id'], access_rules))

    @inspur_driver_debug_trace
    def _update_share_stats(self, data=None):
        """update the backend stats including driver info and pools info"""
        data = {}
        backend_name = self.configuration.safe_get('share_backend_name')
        data['vendor_name'] = self.VENDOR
        data['driver_version'] = self.VERSION
        data['storage_protocol'] = self.PROTOCOL
        data['share_backend_name'] = backend_name
        data['driver_handles_share_servers'] = False
        data['snapshot_support'] = True
        data['create_share_from_snapshot_support'] = True
        pools = []

        pools_in_conf = self.pools
        for pool_b in pools_in_conf:
            pool_stats = self._get_pools_stats(pool_b)
            pools.append(pool_stats)
        data['pools'] = pools
        self._stats = data
        # Driver excute this method every minute, so we set this when the
        # _update_share_stats excute for times ,the driver will refresh
        # the token
        time_difference = time.time() - self._token_time
        if time_difference > self.token_available_time:
            self._rest.refresh_token()
            self._token_time = time.time()
            LOG.debug('Token of Driver has been refreshed')
        LOG.debug('Update share stats : %s' % self._stats)

    @inspur_driver_debug_trace
    def _clear_access(self, share):
        """clear all access of share"""
        pool, share_name, size, proto = self._get_share_pnsp(share)
        share_path = r'/%s/%s' % (pool, share_name)
        if proto == 'nfs':
            share_backend = self._get_nfs_share(share_path)
            client_list = share_backend['clientList']
        elif proto == 'cifs':
            share_backend = self._get_cifs_share(share_name)
            client_list = share_backend['userList']
        method = 'file/share/%s' % proto
        request_type = 'put'
        params = {'addedClientList': [],
                  'deletedClientList': client_list,
                  'editedClientList': []}
        if proto == 'nfs':
            params['path'] = share_path
            params['pathAuthority'] = share_backend['pathAuthority']
        elif proto == 'cifs':
            params['path'] = share_path
            params['name'] = share_name

        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)
        LOG.debug('Clear all the access of share name:%s'
                  % share['id'],)

    @inspur_driver_debug_trace
    def _validate_pools_exist(self):
        """Check the pool in conf exist in the backend"""
        pool_list = self._get_directory_list('/')
        for pool in self.pools:
            if pool not in pool_list:
                msg = '%s is not exist in backend storage.' % pool
                LOG.error(msg)
                raise exception.InvalidInput(reason=msg)

    @inspur_driver_debug_trace
    def _get_directory_quata(self, path):
        """get the quata of directory"""
        method = 'file/quota/directory?path=/%s' % path
        request_type = 'get'
        data = self._rest.send_rest_api(method=method,
                                        request_type=request_type)
        quota = data.get('hardthreshold')
        if quota is None:
            # the method of '_update_share_stats' will check quata of pools.
            # To avoid return NONE for pool info, so raise this exception
            msg = (r'Quota of pool: /%s is not set, '
                   r'please set it in GUI of AS13000' % path)
            LOG.error(msg)
            raise exception.ShareBackendException(reason=msg)
        else:
            hardunit = data.get('hardunit')
            used_capacity = data.get('capacity')
            used_capacity = (str(used_capacity)).upper()
            used_capacity = self._unit_convert(used_capacity)

            if hardunit == 1:
                quota = quota * 1024
            total_capacity = int(quota)
            used_capacity = int(used_capacity)
            return total_capacity, used_capacity

    @inspur_driver_debug_trace
    def _get_pools_stats(self, path):
        """get the stats of pools incloud capacity and other infomations.
        get system instead of get quata"""
        total_capacity, used_capacity = self._get_directory_quata(path)
        #total_capacity, used_capacity = self._get_device_profile()
        free_capacity = total_capacity - used_capacity
        pool = {}
        pool['pool_name'] = path
        pool['reserved_percentage'] = 0
        pool['max_over_subscription_ratio'] = 20.0
        pool['dedupe'] = False
        pool['compression'] = False
        pool['qos'] = False
        pool['thin_provisioning'] = True
        pool['total_capacity_gb'] = total_capacity
        pool['free_capacity_gb'] = free_capacity
        pool['allocated_capacity_gb'] = used_capacity
        pool['snapshot_support'] = True
        pool['create_share_from_snapshot_support'] = True
        return pool

    @inspur_driver_debug_trace
    def _get_directory_list(self, path):
        """ Get all the directory list of target path"""
        method = 'file/directory?path=%s' % path
        request_type = 'get'
        directory_list = self._rest.send_rest_api(method=method,
                                                  request_type=request_type)
        dir_list = []
        for directory in directory_list:
            dir_list.append(directory['name'])
        return dir_list

    @inspur_driver_debug_trace
    def _create_directory(self, share_name, pool_name):
        """create a directory for share"""
        authority_info = {"user": "root",
                          "group": "root",
                          "authority": "rwxrwxrwx"}
        protection_info = self.configuration.directory_protection_info
        if not protection_info:
            msg = 'protection_info is not set!'
            LOG.error(msg)
            raise exception.ShareBackendException(msg)
        protection_type = protection_info.get('type')
        if protection_type == 0:
            required_flags = ['type', 'dc', 'cc', 'rn', 'st']
            for flag in required_flags:
                if flag not in protection_info:
                    msg = '%s is not set.' % flag
                    LOG.error(msg)
                    raise exception.InvalidInput(reason=msg)
        if protection_type == 1:
            required_flags = ['type', 'strategy']
            for flag in required_flags:
                if flag not in protection_info:
                    raise exception.InvalidInput(
                        reason='%s is not set.' % flag)
            if protection_info['strategy'] not in [2, 3]:
                msg = 'Directory Protection strategy is not 2 or 3.'
                LOG.error(msg)
                raise exception.InvalidInput(reason=msg)
        data_protection = protection_info

        method = 'file/directory'
        request_type = 'post'
        params = {'name': share_name,
                  'parentPath': '/%s' % pool_name,
                  'authorityInfo': authority_info,
                  'dataProtection': data_protection,
                  'poolName':self.storage_pool}
        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)
        return r'/%s/%s' % (pool_name, share_name)

    @inspur_driver_debug_trace
    def _delete_directory(self, share_path):
        """delete the directory when delete share"""
        method = 'file/directory?path=%s' % share_path
        request_type = 'delete'
        self._rest.send_rest_api(method=method, request_type=request_type)

    @inspur_driver_debug_trace
    def _set_directory_quota_police(self, share_path, quota):
        """V1.0.1_217_JINAN_police"""
        pass

    @inspur_driver_debug_trace
    def _set_directory_quota(self, share_path, quota):
        """set directory quata for share"""
        method = 'file/quota/directory'
        request_type = 'put'
        params = {'path': share_path, 'hardthreshold': quota, 'hardunit': 2}
        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)

    @inspur_driver_debug_trace
    def _create_nfs_share(self, share_path):
        """create a NFS share"""
        method = 'file/share/nfs'
        request_type = 'post'
        params = {'path': share_path, 'pathAuthority': 'rw', 'client': []}
        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)

    @inspur_driver_debug_trace
    def _delete_nfs_share(self, share_path):
        """Delete the NFS share"""
        method = 'file/share/nfs?path=%s' % share_path
        request_type = 'delete'
        self._rest.send_rest_api(method=method, request_type=request_type)

    @inspur_driver_debug_trace
    def _get_nfs_share(self, share_path):
        """Get the nfs share in backend"""
        method = 'file/share/nfs?path=%s' % share_path
        request_type = 'get'
        share_backend = self._rest.send_rest_api(method=method,
                                                 request_type=request_type)
        return share_backend

    @inspur_driver_debug_trace
    def _create_cifs_share(self, share_name, share_path):
        """Create a CIFS share."""
        method = 'file/share/cifs'
        request_type = 'post'
        params = {'path': share_path,
                  'name': share_name,
                  'userlist': []}
        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)

    @inspur_driver_debug_trace
    def _delete_cifs_share(self, share_name):
        """Delete the CIFS share."""
        method = 'file/share/cifs?name=%s' % share_name
        request_type = 'delete'
        self._rest.send_rest_api(method=method, request_type=request_type)

    @inspur_driver_debug_trace
    def _get_cifs_share(self, share_name):
        """Get the CIFS share in backend"""
        method = 'file/share/cifs?name=%s' % share_name
        request_type = 'get'
        share_backend = self._rest.send_rest_api(method=method,
                                                 request_type=request_type)
        return share_backend

    @inspur_driver_debug_trace
    def _clone_directory_to_dest(self, snapshot, dest_path):
        """Clone the directory to the new directory"""
        source_share = snapshot['share_instance']
        pool = share_utils.extract_host(source_share['host'], level='pool')
        # format the name of new share
        source_name_row = 'share_%s' % snapshot['share_id']
        source_name = self._format_name(source_name_row)
        # format the name of snapshot
        snap_name_row = 'snap_%s' % snapshot['snapshot_id']
        snap_name = self._format_name(snap_name_row)
        snap_path = '/%s/%s' % (pool, source_name)
        method = 'snapshot/directory/clone'
        request_type = 'post'
        params = {'path': snap_path,
                  'snapName': snap_name,
                  'destPath': dest_path}
        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)
        LOG.debug('clone the directory:%s to the new directory: %s'
                  % (snap_path, dest_path))

    @inspur_driver_debug_trace
    def _get_snapshots_from_share(self, path):
        """get all the snapshot of share"""
        method = 'snapshot/directory?path=%s' % path
        request_type = 'get'
        snaps = self._rest.send_rest_api(method=method, request_type=request_type)
        return snaps

    @inspur_driver_debug_trace
    def _get_location_path(self, share_name, share_phth, share_proto):
        """return all the location of all nodes"""
        if share_proto == 'nfs':
            location = [
                {'path': r'%(ips)s:%(share_phth)s'
                         % {'ips': ip, 'share_phth': share_phth}
                 }
                for ip in self.ips
            ]
        elif share_proto == 'cifs':
            location = [
                {'path': r'\\%(ips)s\%(share_name)s' % {
                         'ips': ip,
                         'share_name': share_name}
                 }
                for ip in self.ips
            ]
        else:
            msg = 'Invalid NAS protocol supplied: %s.' % share_proto
            raise exception.InvalidInput(msg)

        return location

    @inspur_driver_debug_trace
    def _get_nodes_ips(self):
        """Get the all nodes ip of backend """
        method = 'cluster/node'
        request_type = 'get'
        cluster = self._rest.send_rest_api(method=method,
                                           request_type=request_type)
        ips = []
        for node in cluster:
            if node['runningStatus'] == 1 and node['healthStatus'] == 1:
                ips.append(node['ip'])
        return ips

    @inspur_driver_debug_trace
    def _get_share_pnsp(self, share):
        """Get pool, share_name, share_size, share_proto of share.
        AS13000 require all the names can only consist of letters,numbers,
        and undercores,and must begin with a letter.
        Also the length of name must less than 32 character.
        The driver will use the ID as the name in backend,
        add 'share_' to the beginning,and convert '-' to '_'
        """
        pool = share_utils.extract_host(share['host'], level='pool')
        share_name_row = 'share_%s' % share['share_id']
        share_name = self._format_name(share_name_row)
        share_size = share['size']
        share_proto = share['share_proto'].lower()
        return pool, share_name, share_size, share_proto

    @inspur_driver_debug_trace
    def _unit_convert(self, capacity):
        """Convert all units to GB"""
        capacity = str(capacity)
        capacity = capacity.upper()
        try:
            unit_of_used = re.findall(r'[A-Z]', capacity)
            unit_of_used = ''.join(unit_of_used)
        except:
            unit_of_used = ''
        capacity = capacity.replace(unit_of_used, '')
        capacity = float(capacity.replace(unit_of_used, ''))
        if unit_of_used in ['B', '']:
            capacity = capacity / units.Gi
        elif unit_of_used in ['K', 'KB']:
            capacity = capacity / units.Mi
        elif unit_of_used in ['M', 'MB']:
            capacity = capacity / units.Ki
        elif unit_of_used in ['G', 'GB']:
            capacity = capacity
        elif unit_of_used in ['T', 'TB']:
            capacity = capacity * units.Ki
        elif unit_of_used in ['E', 'EB']:
            capacity = capacity * units.Mi

        capacity = '%.0f' % capacity
        return float(capacity)

    @inspur_driver_debug_trace
    def _format_name(self, name):
        """format name to meet the backend requirements"""
        name = name[0:29]
        name = name.replace('-', '_')
        return name

    @inspur_driver_debug_trace
    def _get_storage_pool(self, directory):
        method = 'file/directory/detail?path=/%s' % directory
        request_type = 'get'
        path_detail = self._rest.send_rest_api(method=method,
                                               request_type=request_type)
        storage_pool = path_detail[0]['poolName']
        return storage_pool

    @inspur_driver_debug_trace
    def _get_device_profile(self):
        """V1.0.1_217_JINAN_police"""
        method = 'device/profile'
        request_type = 'get'
        profile_data = self._rest.send_rest_api(method=method,
                                                request_type=request_type)
        capacityInfo = profile_data['capacityInfo']
        used_capacity = '%smb' % capacityInfo['used']
        total_capacity = '%smb'% capacityInfo['total']

        used_capacity = self._unit_convert(used_capacity)
        total_capacity = self._unit_convert(total_capacity)
        return total_capacity, used_capacity