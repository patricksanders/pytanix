# coding: utf-8

from __future__ import print_function

import sys
import requests
import json
from pprint import pprint

''' A lightweight Python library for the Nutanix API
'''

class NutanixException(Exception):
    def __init__(self, http_status, code, msg):
        self.http_status = http_status
        self.code = code
        self.msg = msg
    def __str__(self):
        return u'http status: {0}, code: {1} - {2}'.format(
            self.http_status, self.code, self.msg)

class Nutanix(object):
    '''
    '''

    trace = True # Enable tracing?

    def __init__(self, ip, auth=None, requests_session=True):
        '''
        '''
        # TODO: let user set base IP
        self.ip = ip
        self.prefix = 'https://' + ip + ':9440/PrismGateway/services/rest/v1/'
        self._auth = auth

        if isinstance(requests_session, requests.Session):
            self._session = requests_session
        else:
            from requests import api
            self._session = api

    def _auth_headers(self):
        if self._auth:
            return {'Authorization': 'Basic {0}'.format(self._auth)}
        else:
            return {}

    def _internal_call(self, method, url, payload, params):
        args = dict(params=params)
        if not url.startswith('http'):
            url = self.prefix + url
        headers = self._auth_headers()
        headers['Content-Type'] = 'application/json'
        print(headers)

        if payload:
            args['data'] = json.dumps(payload)

        r = self._session.request(method, url, headers=headers, verify=False, **args)

        if self.trace:
            print()
            print(method, r.url)
            if payload:
                print('DATA')
                pprint(payload)

        try:
            r.raise_for_status()
        except:
            raise NutanixException(r.status_code,
                -1, u'%s:\n %s' % (r.url, r.json()['message']))
        if len(r.text) > 0:
            results = r.json()
            if self.trace:
                print('RESP:')
                pprint(results)
            return results
        else:
            return None

    def _get(self, url, args=None, payload=None, **kwargs):
        if args:
            kwargs.update(args)
        return self._internal_call('GET', url, payload, kwargs)

    def _post(self, url, args=None, payload=None, **kwargs):
        if args:
            kwargs.update(args)
        return self._internal_call('POST', url, payload, kwargs)

    def _delete(self, url, args=None, payload=None, **kwargs):
        if args:
            kwargs.update(args)
        return self._internal_call('DELETE', url, payload, kwargs)

    def _put(self, url, args=None, payload=None, **kwargs):
        if args:
            kwargs.update(args)
        return self._internal_call('PUT', url, payload, kwargs)

    def next(self, result):
        if result['next']:
            return self._get(result['next'])
        else:
            return None

    def previous(self, result):
        if result['previous']:
            return self._get(result['previous'])
        else:
            return None

    def _warn(self, msg):
        print('warning:' + msg, file=sys.stderr)

    def alerts(self, **kwargs):
        return self._get('alerts', kwargs)

    def alerts_configuration(self, **kwargs):
        return self._get('alerts/configuration', kwargs)

    def alerts_hardware(self, **kwargs):
        return self._get('alerts/hardware', kwargs)

    def alerts_metadata(self, **kwargs):
        return self._get('alerts/metadata', kwargs)

    def alerts_storage(self, **kwargs):
        return self._get('alerts/storage', kwargs)

    def auth_config(self, **kwargs):
        return self._get('authconfig', kwargs)

    def auth_types(self, **kwargs):
        return self._get('authconfig/auth_types', kwargs)

    def client_auth(self, **kwargs):
        return self._get('authconfig/client_auth', kwargs)

    def auth_directories(self, **kwargs):
        return self._get('authconfig/directories', kwargs)

    def auth_directories(self, name, **kwargs):
        return self._get('authconfig/directories/{0}'.format(name), kwargs)



