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
    Example usage:
        
        import pytanix
        nu = pytanix.Nutanix()
        alerts = nu.alerts()
        print(alerts)
    '''

    trace = True # Enable tracing?

    def __init__(self, ip, auth=None, requests_session=True):
        '''Create a Nutanix REST API object.
        Parameters:
        ip -- A Nutanix cluster or CVM IP address
        auth -- An authorization token (optional)
        requests_session -- A Requests session object of a truthy value to create one.
            A falsy value disables sessions.
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

    def _warn(self, msg):
        print('warning:' + msg, file=sys.stderr)

    ############################################################
    # Alerts
    ############################################################
    def get_alerts(self, **kwargs):
        '''returns a list of alerts
            
        Keyword arguments:
        startTimeInUsecs -- Start time in microseconds
        endTimeInUsecs -- End time in microseconds
        count -- Maximum number of alerts
        resolved -- Alerts which have been resolved
        acknowledged -- Alerts which have been acknowledged
        severity -- Alert severities
        alertTypeUuid -- Alert type ids
        page -- Page number
        entityType -- Entity type
        entityIds -- Entity ids
        '''
        return self._get('alerts', kwargs)

    def acknowledge_alerts(self, **kwargs):
        '''acknowledge alerts using a filter criteria
            
        Keyword arguments:
        startTimeInUsecs -- Start time in microseconds
        endTimeInUsecs -- End time in microseconds
        severity -- Alert severities
        entityType -- Entity type
        entityTypeIds -- Entity type ids
        count -- Maximum number of alerts
        '''
        return self._post('alerts/acknowledge', kwargs)

    def get_alerts_configuration(self):
        '''get the configuration that is used to send alert emails
        '''
        return self._get('alerts/configuration')

    def update_alerts_configuration(self, payload):
        '''update the configuration that is used to send alert emails

        Parameters:
        payload -- json object of new alert configuration
        '''
        return self._put('alerts/configuration', payload=payload)

    def get_hardware_alerts(self, **kwargs):
        '''get the list of hardware alerts generated in the cluster
            
        Keyword arguments:
        startTimeInUsecs -- Start time in microseconds
        endTimeInUsecs -- End time in microseconds
        count -- Maximum number of alerts
        resolved -- Alerts which have been resolved
        acknowledged -- Alerts which have been acknowledged
        severity -- Alert severities
        alertTypeUuid -- Alert type ids
        page -- Page number
        entityType -- Entity type
        entityIds -- Entity ids
        '''
        return self._get('alerts/hardware', kwargs)

    def get_alerts_metadata(self, **kwargs):
        '''get the list of alerts metadata generated in the cluster
            
        Keyword arguments:
        ids -- Alert UUIDs
        excludeDisabled -- Exclude disabled alerts
        '''
        return self._get('alerts/metadata', kwargs)

    def update_alerts_metadata(self, payload):
        '''get the list of alerts metadata generated in the cluster

        Parameters:
        payload -- json object of new alert metadata
        '''
        return self._put('alerts/metadata', payload=payload)

    def get_alerts_metadata(self, alertTypeUuid):
        '''get the list of alerts metadata generated in the cluster

        Parameters:
        alertTypeUuid -- Alert type UUID of the Alert metadata
        '''
        return self._get('alerts/metadata/{0}'.format(alertTypeUuid))

    def resolve_alerts(self, **kwargs):
        '''resolve alerts using a filter criteria
            
        Keyword arguments:
        startTimeInUsecs -- Start time in microseconds
        endTimeInUsecs -- End time in microseconds
        severity -- Alert severities
        entityType -- Entity type
        entityTypeIds -- Entity type ids
        count -- Maximum number of alerts
        '''
        return self._post('alerts/resolve', kwargs)

    def get_storage_alerts(self, **kwargs):
        '''get the list of storage alerts generated in the cluster
            
        Keyword arguments:
        startTimeInUsecs -- Start time in microseconds
        endTimeInUsecs -- End time in microseconds
        count -- Maximum number of alerts
        resolved -- Alerts which have been resolved
        acknowledged -- Alerts which have been acknowledged
        severity -- Alert severities
        alertTypeUuid -- Alert type ids
        page -- Page number
        entityType -- Entity type
        entityIds -- Entity ids
        '''
        return self._get('alerts/storage', kwargs)

    def acknowledge_alert(self, id):
        '''acknowledge alert by id
            
        Parameters:
        id -- Alert id
        '''
        return self._post('alerts/{0}/acknowledge'.format(id))

    def resolve_alert(self, id):
        '''resolve alert by id
            
        Parameters:
        id -- Alert id
        '''
        return self._post('alerts/{0}/resolve'.format(id))

    ############################################################
    # Authentication
    ############################################################
    def get_auth_config(self):
        '''get auth configuration
        '''
        return self._get('authconfig')

    def update_auth_config(self, payload):
        '''update auth configuration

        Parameters:
        payload -- json of updated auth config
        '''
        return self._put('authconfig', payload=payload)

    def delete_auth_config(self):
        '''delete auth configuration
        '''
        return self._delete('authconfig')

    def add_auth_types(self, payload):
        '''add authentication types

        Parameters:
        payload -- json array of auth types
        '''
        return self._post('authconfig/add_auth_types', payload=payload)

    def update_auth_types(self, payload):
        '''add authentication types

        Parameters:
        payload -- json array of auth types
        '''
        return self._put('authconfig/auth_types', payload=payload)

    def get_auth_types(self):
        '''get authentication types
        '''
        return self._get('authconfig/auth_types')

    def set_client_auth_status(self, enable):
        '''enable or disable client authentication

        Parameters:
        enable -- boolean for enabling or disabling client auth
        '''
        payload = {"value": enable}
        return self._post('authconfig/client_auth/', payload=payload)

    def get_client_auth_status(self):
        '''get authentication types
        '''
        return self._get('authconfig/client_auth/')

    def delete_client_auth(self, name):
        '''delete client chain certificate on the cluster

        Parameters:
        name -- name of the certificate
        '''
        return self._delete('authconfig/client_auth/{0}'.format(name))

    def add_auth_directory(self, payload):
        '''add directory config to the cluster

        Parameters:
        payload -- json auth directory config
        '''
        return self._post('authconfig/directories/', payload=payload)

    def edit_auth_directory(self, payload):
        '''edit the specified directory config

        Parameters:
        payload -- json auth directory config
        '''
        return self._put('authconfig/directories/', payload=payload)

    def get_auth_directories(self):
        '''get the list of directories configured in the cluster
        '''
        return self._get('authconfig/directories/')

    def test_auth_connection(self, payload):
        '''test LDAP directory connection status

        Parameters:
        payload -- json containing user, pass, and AD name
        '''
        return self._post('authconfig/directories/connection_status', payload=payload)

    def get_auth_directory(self, name):
        '''get directory with the specified name
        
        Parameters:
        name -- name of directory
        '''
        return self._get('authconfig/directories/{0}'.format(name))

    def delete_auth_directory(self, name):
        '''delete directory with the specified name
        
        Parameters:
        name -- name of directory
        '''
        return self._delete('authconfig/directories/{0}'.format(name))

    def remove_auth_types(self, payload):
        '''remove auth types from the existing auth types

        Parameters:
        payload -- json containing user, pass, and AD name
        '''
        return self._post('authconfig/remove_auth_types', payload=payload)

    ############################################################
    # Certificates
    ############################################################

    ############################################################
    # Cloud
    ############################################################

    ############################################################
    # Cluster
    ############################################################

    ############################################################
    # Clusters
    ############################################################

    ############################################################
    # Containers
    ############################################################

    ############################################################
    # Disks
    ############################################################

    ############################################################
    # Encryption
    ############################################################

    ############################################################
    # Events
    ############################################################

    ############################################################
    # Health Checks
    ############################################################

    ############################################################
    # Hosts
    ############################################################

    ############################################################
    # HTTP Proxies
    ############################################################

    ############################################################
    # Key Management Servers
    ############################################################

    ############################################################
    # License
    ############################################################

    ############################################################
    # Protection Domains
    ############################################################

    ############################################################
    # Pulse
    ############################################################

    ############################################################
    # Remote Sites
    ############################################################

    ############################################################
    # SMB Server
    ############################################################

    ############################################################
    # SNMP
    ############################################################

    ############################################################
    # Storage Pools
    ############################################################

    ############################################################
    # Upgrade
    ############################################################

    ############################################################
    # vDisks
    ############################################################

    ############################################################
    # Virtual Disks
    ############################################################

    ############################################################
    # VMs
    ############################################################

    ############################################################
    # vStores
    ############################################################

