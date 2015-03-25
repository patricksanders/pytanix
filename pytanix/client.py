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

    trace = False
    verify_ssl = True

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
        # put params in args
        args = dict(params=params)
        if not url.startswith('http'):
            url = self.prefix + url

        # set headers
        headers = self._auth_headers()
        headers['Content-Type'] = 'application/json'
        if self.trace:
            print('HEADERS')
            pprint(headers)

        # add payload to args
        if payload:
            args['data'] = json.dumps(payload)

        r = self._session.request(method, url, headers=headers, verify=self.verify_ssl, **args)

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
                print('RESP')
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
    def get_ca_certs(self):
        '''get all CA certificates from cluster
        '''
        return self._get('certificates/ca_certificates/')

    def add_ca_cert(self, name, cert):
        '''add trusted CA certificate to the cluster
        '''
        #TODO: Handle this. (need to accept cert file)
        pass

    def delete_ca_cert(self, name):
        '''delete a CA certificate from the cluster

        Parameters:
        name -- Certificate Authority name
        '''
        return self._delete('certificates/ca_certificates/{0}'.format(name))

    def update_cert_info(self, payload):
        '''update the certification information

        Parameters:
        payload -- json certification information
        '''
        return self._put('certificates/certification_information', payload=payload)

    def get_cert_info(self):
        '''get certificate signing information
        '''
        return self._get('certificates/certification_information/')

    def get_node_csr(self, **kwargs):
        '''download csr for node with given ip

        Keyword Arguments:
        nodeIp -- IP address of node
        '''
        return self._get('certificates/csr_for_discovered_node', kwargs)

    def get_cluster_csrs(self, **kwargs):
        '''download csr files from cluster

        Keyword Arguments:
        nodeIdList -- list of node IDs
        '''
        return self._get('certificates/csrs', kwargs)

    def delete_svm_cert(self, **kwargs):
        '''delete an svm certificate from cluster

        Keyword Arguments:
        nodeId -- id of the node on which the cert is installed
        serverName -- key management server for which cert is installed
        '''
        return self._delete('certificate/svm_certificate/', kwargs)
    
    def add_svm_cert(self, kms_name, cert):
        '''add certificate to the cluster
        '''
        #TODO: Handle this. (need to accept cert file)
        #TODO: Also handle multi-cert upload
        pass

    ############################################################
    # Cloud
    ############################################################

    ############################################################
    # Cluster
    ############################################################
    def get_cluster(self):
        '''get cluster details
        '''
        return self._get('/cluster/')

    def update_cluster(self, payload):
        '''update cluster details

        Parameters:
        payload -- cluster detail json
        '''
        return self._put('/cluster/', payload=payload)

    def cluster_domain(self, payload):
        '''join/unjoin the storage cluster to/from a Windows AD domain

        Parameters:
        payload -- information pertaining to the Windows AD domain
        '''
        return self._put('cluster/cluster_domain', payload=payload)

    def get_cluster_nameservers(self):
        '''get the list of nameservers configured on the cluster
        '''
        return self._get('cluster/name_servers')

    def add_cluster_nameserver(self, server):
        '''add a nameserver to the cluster

        Parameters:
        server -- address of nameserver
        '''
        payload = {"value": server}
        return self._post('cluster/name_servers', payload=payload)

    def delete_cluster_nameserver(self, server):
        '''delete a nameserver with the specified name
        
        Parameters:
        server -- name of nameserver to delete
        '''
        return self._delete('cluster/name_servers/{0}'.format(server))

    def get_nfs_whitelist(self):
        '''get the NFS subnet whitelist on the cluster
        '''
        return self._get('cluster/nfs_whitelist')

    def add_nfs_whitelist(self, entry):
        '''add an address to the NFS subnet whitelist

        Parameters:
        entry -- value to add to NFS whitelist
        '''
        payload = {"value": entry}
        return self._post('cluster/nfs_whitelist', payload=payload)

    def delete_nfs_whitelist(self, name):
        '''delete an address from the NFS subnet whitelist
        
        Parameters:
        name -- NFS whitelist entry to delete
        '''
        return self._delete('cluster/nfs_whitelist/{0}'.format(name))

    def get_ntp_servers(self):
        '''get the list of NTP servers for the cluster
        '''
        return self._get('cluster/ntp_servers')

    def add_ntp_server(self, server):
        '''add NTP server to the cluster

        Parameters:
        server -- NTP server to add to the cluster
        '''
        payload = {"value": server}
        return self._post('cluster/ntp_servers', payload=payload)

    def delete_ntp_server(self, server):
        '''remove NTP server from the cluster

        Parameters:
        server -- NTP server to be removed from the cluster
        '''
        return self._delete('cluster/ntp_servers/{0}'.format(server))

    def get_public_keys(self):
        '''get cluster's public keys
        '''
        return self._get('cluster/public_keys/')

    def add_public_key(self, name, key):
        '''add a public key to the cluster

        Parameters:
        name -- name for the public key
        key -- key to be added
        '''
        payload = {"name": name, "key": key}
        return self._post('cluster/public_keys/', payload=payload)

    def delete_public_key(self, name):
        '''delete a public key from the cluster

        Parameters:
        name -- name of the key to be deleted
        '''
        return self._delete('cluster/public_keys/{0}'.format(name))

    def get_public_key(self, name):
        '''get a public key by name

        Parameters:
        name -- name of public key
        '''
        return self._get('cluster/public_keys/{0}'.format(name))

    def get_rackable_units(self):
        '''get a list of rackable units configured on the cluster
        '''
        return self._get('cluster/rackable_units')

    def get_rackable_unit(self, id):
        '''get a rackable unit with the specified ID
        
        Parameters:
        id -- ID of a rackable unit
        '''
        return self._get('cluster/rackable_units/{0}'.format(id))

    def delete_rackable_unit(self, id):
        '''delete a rackable unit with the specified ID
        
        Parameters:
        id -- ID of a rackable unit
        '''
        return self._delete('cluster/rackable_units/{0}'.format(id))

    def get_remote_support_status(self):
        '''get the status of remote support settings on the cluster
        '''
        return self._get('cluster/remote_support')
        
    def update_remote_support(self, payload):
        '''update the remote support settings on the cluster

        Parameters:
        payload -- a timed bool instance
        '''
        return self._put('cluster/remote_support', payload=payload)

    def search(self, **kwargs):
        '''perform a spotlight search on the cluster

        Keyword Arguments:
        searchString (required) -- search string
        entityTypes -- entity types
        fieldNames -- field names
        '''
        return self._get('cluster/search/', kwargs)

    def send_email(self, payload):
        '''send an email using the smtp server configuration

        Parameters:
        payload -- json email instance
        '''
        return self._post('cluster/send_email', payload=payload)

    def get_smtp_config(self):
        '''get the SMTP server configuration
        '''
        return self._get('cluster/smtp')

    def update_smtp_config(self, payload):
        '''update the cluster SMTP server configuration

        Parameters:
        payload -- json SMTP server configuration
        '''
        return self._put('/cluster/smtp', payload=payload)

    def delete_smtp_config(self):
        '''delete the cluster's SMTP server configuration
        '''
        return self._delete('/cluster/smtp')

    def get_smtp_security_modes(self):
        '''get the list of supported security modes for the SMTP server
        '''
        return self._get('cluster/smtp/security_modes')

    def get_cluster_stats(self, **kwargs):
        '''get the list of cluster stats

        Keyword Arguments:
        metrics (required) -- list of metrics
        startTimeInUsecs (required) -- start time in microseconds
        endTimeInUsecs (required) -- end time in microseconds
        intervalInSecs (required) -- sampling interval of stats
        '''
        return self._get('cluster/stats/', kwargs)

    ############################################################
    # Clusters
    ############################################################
    def get_clusters(self, **kwargs):
        '''get the list of clusters

        Keyword arguments:
        count -- number of clusters to retrieve
        filterCriteria -- filter criteria
        sortCriteria -- sort criteria
        searchString -- search string
        page -- page number
        projection -- projections on the attributes
        '''
        return self._get('clusters/', kwargs)

    def get_cluster_alerts(self, **kwargs):
        '''get the list of alerts generated on any cluster

        Keyword arguments:
        startTimeInUsecs -- Start time in microseconds
        endTimeInUsecs -- End time in microseconds
        count -- Maximum number of alerts
        resolved -- Alerts which have been resolved
        acknowledged -- Alerts which have been acknowledged
        severity -- Alert severities
        alertTypeUuid -- Alert type ids
        page -- Page number
        '''
        return self._get('clusters/alerts')

    def get_clusters_events(self, **kwargs):
        '''get the list of events generated on any cluster

        Keyword arguments:
        startTimeInUsecs -- Start time in microseconds
        endTimeInUsecs -- End time in microseconds
        count -- Maximum number of events
        acknowledged -- Events which have been acknowledged
        page -- Page number
        '''
        return self._get('clusters/events', kwargs)

    def get_cluster_by_id(self, id, **kwargs):
        '''get a cluster
        
        Parameters:
        id -- id of the cluster

        Keyword arguments:
        projection -- projections on the attributes
        '''
        return self._get('clusters/{id}'.format(id), kwargs)

    def get_cluster_alerts(self, id, **kwargs):
        '''get the list of alerts generated on a specified cluster

        Parameters:
        id -- id of the cluster

        Keyword arguments:
        startTimeInUsecs -- Start time in microseconds
        endTimeInUsecs -- End time in microseconds
        count -- Maximum number of alerts
        resolved -- Alerts which have been resolved
        acknowledged -- Alerts which have been acknowledged
        severity -- Alert severities
        alertTypeUuid -- Alert type ids
        page -- Page number
        '''
        return self._get('clusters/{id}/alerts'.format(id), kwargs)

    def get_cluster_events(self, id, **kwargs):
        '''get the list of events generated on a specified cluster

        Parameters:
        id -- id of the cluster

        Keyword arguments:
        startTimeInUsecs -- Start time in microseconds
        endTimeInUsecs -- End time in microseconds
        count -- Maximum number of events
        acknowledged -- Events which have been acknowledged
        page -- Page number
        '''
        return self._get('clusters/{id}/events'.format(id), kwargs)
        
    def get_cluster_stats(self, id, **kwargs):
        '''get the stats for a specified cluster

        Parameters:
        id -- id of the cluster

        Keyword arguments:
        metrics (required) -- list of metrics
        startTimeInUsecs -- Start time in microseconds
        endTimeInUsecs -- End time in microseconds
        intervalInSecs -- sampling interval of stats
        '''
        return self._get('clusters/{id}/stats'.format(id), kwargs)

    ############################################################
    # Containers
    ############################################################
    def get_containers(self, **kwargs):
        '''get the list of containers

        Keyword arguments:
        count -- number of containers to retrieve
        filterCriteria -- filter criteria
        sortCriteria -- sort criteria
        searchString -- search string
        page -- page number
        projection -- projections on the attributes
        '''
        return self._get('containers/', kwargs)

    def add_container(self, payload):
        '''add a container to the cluster

        Parameters:
        payload -- json container configuration
        '''
        return self._post('container/', payload=payload)

    def update_container(self, payload):
        '''update a container's configuration

        Parameters:
        payload -- json container configuration
        '''
        return self._put('container/', payload=payload)

    def get_container_alerts(self, **kwargs):
        '''get the list of alerts generated on any container

        Keyword arguments:
        startTimeInUsecs -- Start time in microseconds
        endTimeInUsecs -- End time in microseconds
        count -- Maximum number of alerts
        resolved -- Alerts which have been resolved
        acknowledged -- Alerts which have been acknowledged
        severity -- Alert severities
        alertTypeUuid -- Alert type ids
        page -- Page number
        '''
        return self._get('containers/alerts', kwargs)

    def get_datastores(self):
        '''get the list of NFS datastores mounted using containers in the cluster
        '''
        return self._get('containers/datastores')

    def add_datastore(self, payload):
        '''add an NFS datastore

        Paramaters:
        payload -- json datastore configuration
        '''
        return self._post('containers/datastores/add_datastore', payload=payload)

    def remove_datastore(self, payload):
        '''remove an NFS datastore

        Parameters:
        payload -- json removal request
        '''
        return self._post('containers/datastores/remove_datastore', payload=payload)

    def get_container_events(self, **kwargs):
        '''get the list of events generated on any container

        Keyword arguments:
        startTimeInUsecs -- Start time in microseconds
        endTimeInUsecs -- End time in microseconds
        count -- Maximum number of events
        acknowledged -- Events which have been acknowledged
        page -- Page number
        '''
        return self._get('containers/events', kwargs)

    def delete_container(self, id, **kwargs):
        '''delete a container with the specified ID from the cluster

        Parameters:
        id -- ID of the container

        Keyword arguments:
        ignoreSmallFiles -- ignore small files
        ignoreVDisks -- ignore all vdisks
        '''
        return self._delete('containers/{0}'.format(id), kwargs)

    def get_container(self, id, **kwargs):
        '''get a container with the specified ID

        Parameters:
        id -- id of the container

        Keyword arguments:
        projection -- projections on the attributes
        '''
        return self._get('containers/{0}'.format(id), kwargs)

    def get_container_alerts(self, id, **kwargs):
        '''get the list of alerts generated on any container

        Parameters:
        id -- id of the container

        Keyword arguments:
        startTimeInUsecs -- Start time in microseconds
        endTimeInUsecs -- End time in microseconds
        count -- Maximum number of alerts
        resolved -- Alerts which have been resolved
        acknowledged -- Alerts which have been acknowledged
        severity -- Alert severities
        alertTypeUuid -- Alert type ids
        page -- Page number
        '''
        return self._get('containers/{0}/alerts'.format(id), kwargs)

    def get_container_events(self, id, **kwargs):
        '''get the list of events generated on any container

        Parameters:
        id -- id of the container

        Keyword arguments:
        startTimeInUsecs -- Start time in microseconds
        endTimeInUsecs -- End time in microseconds
        count -- Maximum number of events
        acknowledged -- Events which have been acknowledged
        page -- Page number
        '''
        return self._get('containers/{0}/events'.format(id), kwargs)

    def get_container_stats(self, id, **kwargs):
        '''get the stats for a specified container

        Parameters:
        id -- id of the container

        Keyword arguments:
        metrics (required) -- List of metrics
        startTimeInUsecs -- Start time in microseconds
        endTimeInUsecs -- End time in microseconds
        intervalInSecs -- Sampling interval of stats
        '''
        return self._get('containers/{0}/stats/'.format(id), kwargs)

    def get_container_vdisks(self, id):
        '''get the list of vDisks of the specified container

        Parameters:
        id -- id of the container
        '''
        return self._get('containers/{0}/vdisks'.format(id))

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

