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
    Example usage::
        
        import pytanix
        nu = pytanix.Nutanix('1.2.3.4')
        alerts = nu.alerts()
        print(alerts)
    '''

    trace = False
    verify_ssl = True

    def __init__(self, ip, auth=None, requests_session=True):
        '''Create a Nutanix REST API object.

        :param ip:
            A Nutanix cluster or CVM IP address
        :type ip: ``string``
        :param auth:
            An authorization token (optional)
        :param requests_session:
            A Requests session object of a truthy value to create one.
            A falsy value disables sessions.
        '''
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

    def _internal_call(self, method, url, payload, files, params):
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

        r = self._session.request(method, url, headers=headers, files=files, verify=self.verify_ssl, **args)

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

    def _get(self, url, args=None, payload=None, files=None, **kwargs):
        if args:
            kwargs.update(args)
        return self._internal_call('GET', url, payload, kwargs)

    def _post(self, url, args=None, payload=None, files=None, **kwargs):
        if args:
            kwargs.update(args)
        return self._internal_call('POST', url, payload, kwargs)

    def _delete(self, url, args=None, payload=None, files=None, **kwargs):
        if args:
            kwargs.update(args)
        return self._internal_call('DELETE', url, payload, kwargs)

    def _put(self, url, args=None, payload=None, files=None, **kwargs):
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
            
        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :type startTimeInUsecs: ``int``
        :param endTimeInUsecs:
            End time in microseconds
        :type endTimeInUsecs: ``int``
        :param count:
            Maximum number of alerts
        :type count: ``int``
        :param resolved:
            Alerts which have been resolved
        :type resolved: ``boolean``
        :param acknowledged:
            Alerts which have been acknowledged
        :type acknowledged: ``boolean``
        :param severity:
            Alert severities
        :type severity: ``list``
        :param alertTypeUuid:
            Alert type ids
        :type alertTypeUuid: ``list``
        :param page:
            Page number
        :type page: ``int``
        :param entityType:
            Entity type
        :type entityType: ``str``
        :param entityIds:
            Entity ids
        :type entityIds: ``list``
        '''
        return self._get('alerts', kwargs)

    def acknowledge_alerts(self, **kwargs):
        '''acknowledge alerts using a filter criteria
            
        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param severity:
            Alert severities
        :param entityType:
            Entity type
        :param entityTypeIds:
            Entity type ids
        :param count:
            Maximum number of alerts
        '''
        return self._post('alerts/acknowledge', kwargs)

    def get_alerts_configuration(self):
        '''get the configuration that is used to send alert emails
        '''
        return self._get('alerts/configuration')

    def update_alerts_configuration(self, payload):
        '''update the configuration that is used to send alert emails

        :param payload:
            json object of new alert configuration
        '''
        return self._put('alerts/configuration', payload=payload)

    def get_hardware_alerts(self, **kwargs):
        '''get the list of hardware alerts generated in the cluster
            
        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of alerts
        :param resolved:
            Alerts which have been resolved
        :param acknowledged:
            Alerts which have been acknowledged
        :param severity:
            Alert severities
        :param alertTypeUuid:
            Alert type ids
        :param page:
            Page number
        :param entityType:
            Entity type
        :param entityIds:
            Entity ids
        '''
        return self._get('alerts/hardware', kwargs)

    def get_alerts_metadata(self, **kwargs):
        '''get the list of alerts metadata generated in the cluster
            
        Kwargs:

        :param ids:
            Alert UUIDs
        :param excludeDisabled:
            Exclude disabled alerts
        '''
        return self._get('alerts/metadata', kwargs)

    def update_alerts_metadata(self, payload):
        '''get the list of alerts metadata generated in the cluster

        :param payload:
            json object of new alert metadata
        '''
        return self._put('alerts/metadata', payload=payload)

    def get_alerts_metadata(self, alertTypeUuid):
        '''get the list of alerts metadata generated in the cluster

        :param alertTypeUuid:
            Alert type UUID of the Alert metadata
        '''
        return self._get('alerts/metadata/{0}'.format(alertTypeUuid))

    def resolve_alerts(self, **kwargs):
        '''resolve alerts using a filter criteria
            
        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param severity:
            Alert severities
        :param entityType:
            Entity type
        :param entityTypeIds:
            Entity type ids
        :param count:
            Maximum number of alerts
        '''
        return self._post('alerts/resolve', kwargs)

    def get_storage_alerts(self, **kwargs):
        '''get the list of storage alerts generated in the cluster
            
        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of alerts
        :param resolved:
            Alerts which have been resolved
        :param acknowledged:
            Alerts which have been acknowledged
        :param severity:
            Alert severities
        :param alertTypeUuid:
            Alert type ids
        :param page:
            Page number
        :param entityType:
            Entity type
        :param entityIds:
            Entity ids
        '''
        return self._get('alerts/storage', kwargs)

    def acknowledge_alert(self, id):
        '''acknowledge alert by id
            
        :param id:
            Alert id
        '''
        return self._post('alerts/{0}/acknowledge'.format(id))

    def resolve_alert(self, id):
        '''resolve alert by id
            
        :param id:
            Alert id
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

        :param payload:
            json of updated auth config
        '''
        return self._put('authconfig', payload=payload)

    def delete_auth_config(self):
        '''delete auth configuration
        '''
        return self._delete('authconfig')

    def add_auth_types(self, payload):
        '''add authentication types

        :param payload:
            json array of auth types
        '''
        return self._post('authconfig/add_auth_types', payload=payload)

    def update_auth_types(self, payload):
        '''add authentication types

        :param payload:
            json array of auth types
        '''
        return self._put('authconfig/auth_types', payload=payload)

    def get_auth_types(self):
        '''get authentication types
        '''
        return self._get('authconfig/auth_types')

    def set_client_auth_status(self, enable):
        '''enable or disable client authentication

        :param enable:
            boolean for enabling or disabling client auth
        '''
        payload = {"value": enable}
        return self._post('authconfig/client_auth/', payload=payload)

    def get_client_auth_status(self):
        '''get authentication types
        '''
        return self._get('authconfig/client_auth/')

    def delete_client_auth(self, name):
        '''delete client chain certificate on the cluster

        :param name:
            name of the certificate
        '''
        return self._delete('authconfig/client_auth/{0}'.format(name))

    def add_auth_directory(self, payload):
        '''add directory config to the cluster

        :param payload:
            json auth directory config
        '''
        return self._post('authconfig/directories/', payload=payload)

    def edit_auth_directory(self, payload):
        '''edit the specified directory config

        :param payload:
            json auth directory config
        '''
        return self._put('authconfig/directories/', payload=payload)

    def get_auth_directories(self):
        '''get the list of directories configured in the cluster
        '''
        return self._get('authconfig/directories/')

    def test_auth_connection(self, payload):
        '''test LDAP directory connection status

        :param payload:
            json containing user, pass, and AD name
        '''
        return self._post('authconfig/directories/connection_status', payload=payload)

    def get_auth_directory(self, name):
        '''get directory with the specified name
        
        :param name:
            name of directory
        '''
        return self._get('authconfig/directories/{0}'.format(name))

    def delete_auth_directory(self, name):
        '''delete directory with the specified name
        
        :param name:
            name of directory
        '''
        return self._delete('authconfig/directories/{0}'.format(name))

    def remove_auth_types(self, payload):
        '''remove auth types from the existing auth types

        :param payload:
            json containing user, pass, and AD name
        '''
        return self._post('authconfig/remove_auth_types', payload=payload)

    ############################################################
    # Certificates
    ############################################################
    def get_ca_certs(self):
        '''get all CA certificates from cluster
        '''
        return self._get('certificates/ca_certificates/')

    def add_ca_cert(self, cert, **kwargs):
        '''add trusted CA certificate to the cluster

        :param cert:
            file object of certificate, rb mode
        :type cert: ``file``

        Kwargs:

        :param name:
            cert name
        :type name: ``str``
        '''
        files = {'file': cert}
        return self._post('certificates/ca_certificates/', kwargs, files=files)

    def delete_ca_cert(self, name):
        '''delete a CA certificate from the cluster

        :param name:
            Certificate Authority name
        '''
        return self._delete('certificates/ca_certificates/{0}'.format(name))

    def update_cert_info(self, payload):
        '''update the certification information

        :param payload:
            json certification information
        '''
        return self._put('certificates/certification_information', payload=payload)

    def get_cert_info(self):
        '''get certificate signing information
        '''
        return self._get('certificates/certification_information/')

    def get_node_csr(self, **kwargs):
        '''download csr for node with given ip

        Kwargs:

        :param nodeIp:
            IP address of node
        '''
        return self._get('certificates/csr_for_discovered_node', kwargs)

    def get_cluster_csrs(self, **kwargs):
        '''download csr files from cluster

        Kwargs:

        :param nodeIdList:
            list of node IDs
        '''
        return self._get('certificates/csrs', kwargs)

    def delete_svm_cert(self, **kwargs):
        '''delete an svm certificate from cluster

        Kwargs:

        :param nodeId:
            id of the node on which the cert is installed
        :param serverName:
            key management server for which cert is installed
        '''
        return self._delete('certificate/svm_certificate/', kwargs)
    
    def add_svm_cert(self, cert, **kwargs):
        '''add certificate to the cluster

        :param cert:
            file object of certificate, rb mode
        :type cert: ``file``

        Kwargs:

        :param keyManagementServerName:
            key management server name
        :type keyManagementServerName: ``str``
        '''
        files = {'file': cert}
        return self._post('certificates/svm_certificates/', kwargs, files=files)

    def add_svm_certs(self, certs, **kwargs):
        '''add multiple certificates to the cluster

        :param certs:
            file objects of certificate, rb mode
        :type cert: ``[file]``
        '''
        return self._post('certificates/svm_certificates/', kwargs, files=certs)

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

        :param payload:
            cluster detail json
        '''
        return self._put('/cluster/', payload=payload)

    def cluster_domain(self, payload):
        '''join/unjoin the storage cluster to/from a Windows AD domain

        :param payload:
            information pertaining to the Windows AD domain
        '''
        return self._put('cluster/cluster_domain', payload=payload)

    def get_cluster_nameservers(self):
        '''get the list of nameservers configured on the cluster
        '''
        return self._get('cluster/name_servers')

    def add_cluster_nameserver(self, server):
        '''add a nameserver to the cluster

        :param server:
            address of nameserver
        '''
        payload = {"value": server}
        return self._post('cluster/name_servers', payload=payload)

    def delete_cluster_nameserver(self, server):
        '''delete a nameserver with the specified name
        
        :param server:
            name of nameserver to delete
        '''
        return self._delete('cluster/name_servers/{0}'.format(server))

    def get_nfs_whitelist(self):
        '''get the NFS subnet whitelist on the cluster
        '''
        return self._get('cluster/nfs_whitelist')

    def add_nfs_whitelist(self, entry):
        '''add an address to the NFS subnet whitelist

        :param entry:
            value to add to NFS whitelist
        '''
        payload = {"value": entry}
        return self._post('cluster/nfs_whitelist', payload=payload)

    def delete_nfs_whitelist(self, name):
        '''delete an address from the NFS subnet whitelist
        
        :param name:
            NFS whitelist entry to delete
        '''
        return self._delete('cluster/nfs_whitelist/{0}'.format(name))

    def get_ntp_servers(self):
        '''get the list of NTP servers for the cluster
        '''
        return self._get('cluster/ntp_servers')

    def add_ntp_server(self, server):
        '''add NTP server to the cluster

        :param server:
            NTP server to add to the cluster
        '''
        payload = {"value": server}
        return self._post('cluster/ntp_servers', payload=payload)

    def delete_ntp_server(self, server):
        '''remove NTP server from the cluster

        :param server:
            NTP server to be removed from the cluster
        '''
        return self._delete('cluster/ntp_servers/{0}'.format(server))

    def get_public_keys(self):
        '''get cluster's public keys
        '''
        return self._get('cluster/public_keys/')

    def add_public_key(self, name, key):
        '''add a public key to the cluster

        :param name:
            name for the public key
        :param key:
            key to be added
        '''
        payload = {"name": name, "key": key}
        return self._post('cluster/public_keys/', payload=payload)

    def delete_public_key(self, name):
        '''delete a public key from the cluster

        :param name:
            name of the key to be deleted
        '''
        return self._delete('cluster/public_keys/{0}'.format(name))

    def get_public_key(self, name):
        '''get a public key by name

        :param name:
            name of public key
        '''
        return self._get('cluster/public_keys/{0}'.format(name))

    def get_rackable_units(self):
        '''get a list of rackable units configured on the cluster
        '''
        return self._get('cluster/rackable_units')

    def get_rackable_unit(self, id):
        '''get a rackable unit with the specified ID
        
        :param id:
            ID of a rackable unit
        '''
        return self._get('cluster/rackable_units/{0}'.format(id))

    def delete_rackable_unit(self, id):
        '''delete a rackable unit with the specified ID
        
        :param id:
            ID of a rackable unit
        '''
        return self._delete('cluster/rackable_units/{0}'.format(id))

    def get_remote_support_status(self):
        '''get the status of remote support settings on the cluster
        '''
        return self._get('cluster/remote_support')
        
    def update_remote_support(self, payload):
        '''update the remote support settings on the cluster

        :param payload:
            a timed bool instance
        '''
        return self._put('cluster/remote_support', payload=payload)

    def search(self, **kwargs):
        '''perform a spotlight search on the cluster

        Kwargs:

            searchString (str): search string
        :param entityTypes:
            entity types
        :param fieldNames:
            field names
        '''
        return self._get('cluster/search/', kwargs)

    def send_email(self, payload):
        '''send an email using the smtp server configuration

        :param payload:
            json email instance
        '''
        return self._post('cluster/send_email', payload=payload)

    def get_smtp_config(self):
        '''get the SMTP server configuration
        '''
        return self._get('cluster/smtp')

    def update_smtp_config(self, payload):
        '''update the cluster SMTP server configuration

        :param payload:
            json SMTP server configuration
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

        Kwargs:

        :param metrics:
            (required) list of metrics
        :param startTimeInUsecs:
            (required) start time in microseconds
        :param endTimeInUsecs:
            (required) end time in microseconds
        :param intervalInSecs:
            (required) sampling interval of stats
        '''
        return self._get('cluster/stats/', kwargs)

    ############################################################
    # Clusters
    ############################################################
    def get_clusters(self, **kwargs):
        '''get the list of clusters

        Kwargs:

        :param count:
            number of clusters to retrieve
        :param filterCriteria:
            filter criteria
        :param sortCriteria:
            sort criteria
        :param searchString:
            search string
        :param page:
            page number
        :param projection:
            projections on the attributes
        '''
        return self._get('clusters/', kwargs)

    def get_cluster_alerts(self, **kwargs):
        '''get the list of alerts generated on any cluster

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of alerts
        :param resolved:
            Alerts which have been resolved
        :param acknowledged:
            Alerts which have been acknowledged
        :param severity:
            Alert severities
        :param alertTypeUuid:
            Alert type ids
        :param page:
            Page number
        '''
        return self._get('clusters/alerts')

    def get_clusters_events(self, **kwargs):
        '''get the list of events generated on any cluster

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of events
        :param acknowledged:
            Events which have been acknowledged
        :param page:
            Page number
        '''
        return self._get('clusters/events', kwargs)

    def get_cluster_by_id(self, id, **kwargs):
        '''get a cluster
        
        :param id:
            id of the cluster

        Kwargs:

        :param projection:
            projections on the attributes
        '''
        return self._get('clusters/{id}'.format(id), kwargs)

    def get_cluster_alerts(self, id, **kwargs):
        '''get the list of alerts generated on a specified cluster

        :param id:
            id of the cluster

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of alerts
        :param resolved:
            Alerts which have been resolved
        :param acknowledged:
            Alerts which have been acknowledged
        :param severity:
            Alert severities
        :param alertTypeUuid:
            Alert type ids
        :param page:
            Page number
        '''
        return self._get('clusters/{id}/alerts'.format(id), kwargs)

    def get_cluster_events(self, id, **kwargs):
        '''get the list of events generated on a specified cluster

        :param id:
            id of the cluster

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of events
        :param acknowledged:
            Events which have been acknowledged
        :param page:
            Page number
        '''
        return self._get('clusters/{id}/events'.format(id), kwargs)
        
    def get_cluster_stats(self, id, **kwargs):
        '''get the stats for a specified cluster

        :param id:
            id of the cluster

        Kwargs:

        :param metrics:
            (required) list of metrics
        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param intervalInSecs:
            sampling interval of stats
        '''
        return self._get('clusters/{id}/stats'.format(id), kwargs)

    ############################################################
    # Containers
    ############################################################
    def get_containers(self, **kwargs):
        '''get the list of containers

        Kwargs:

        :param count:
            number of containers to retrieve
        :param filterCriteria:
            filter criteria
        :param sortCriteria:
            sort criteria
        :param searchString:
            search string
        :param page:
            page number
        :param projection:
            projections on the attributes
        '''
        return self._get('containers/', kwargs)

    def add_container(self, payload):
        '''add a container to the cluster

        :param payload:
            json container configuration
        '''
        return self._post('container/', payload=payload)

    def update_container(self, payload):
        '''update a container's configuration

        :param payload:
            json container configuration
        '''
        return self._put('container/', payload=payload)

    def get_container_alerts(self, **kwargs):
        '''get the list of alerts generated on any container

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of alerts
        :param resolved:
            Alerts which have been resolved
        :param acknowledged:
            Alerts which have been acknowledged
        :param severity:
            Alert severities
        :param alertTypeUuid:
            Alert type ids
        :param page:
            Page number
        '''
        return self._get('containers/alerts', kwargs)

    def get_datastores(self):
        '''get the list of NFS datastores mounted using containers in the cluster
        '''
        return self._get('containers/datastores')

    def add_datastore(self, payload):
        '''add an NFS datastore

        :param payload:
            json datastore configuration
        '''
        return self._post('containers/datastores/add_datastore', payload=payload)

    def remove_datastore(self, payload):
        '''remove an NFS datastore

        :param payload:
            json removal request
        '''
        return self._post('containers/datastores/remove_datastore', payload=payload)

    def get_container_events(self, **kwargs):
        '''get the list of events generated on any container

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of events
        :param acknowledged:
            Events which have been acknowledged
        :param page:
            Page number
        '''
        return self._get('containers/events', kwargs)

    def delete_container(self, id, **kwargs):
        '''delete a container with the specified ID from the cluster

        :param id:
            ID of the container

        Kwargs:

        :param ignoreSmallFiles:
            ignore small files
        :param ignoreVDisks:
            ignore all vdisks
        '''
        return self._delete('containers/{0}'.format(id), kwargs)

    def get_container(self, id, **kwargs):
        '''get a container with the specified ID

        :param id:
            id of the container

        Kwargs:

        :param projection:
            projections on the attributes
        '''
        return self._get('containers/{0}'.format(id), kwargs)

    def get_container_alerts(self, id, **kwargs):
        '''get the list of alerts generated on any container

        :param id:
            id of the container

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of alerts
        :param resolved:
            Alerts which have been resolved
        :param acknowledged:
            Alerts which have been acknowledged
        :param severity:
            Alert severities
        :param alertTypeUuid:
            Alert type ids
        :param page:
            Page number
        '''
        return self._get('containers/{0}/alerts'.format(id), kwargs)

    def get_container_events(self, id, **kwargs):
        '''get the list of events generated on any container

        :param id:
            id of the container

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of events
        :param acknowledged:
            Events which have been acknowledged
        :param page:
            Page number
        '''
        return self._get('containers/{0}/events'.format(id), kwargs)

    def get_container_stats(self, id, **kwargs):
        '''get the stats for a specified container

        :param id:
            id of the container

        Kwargs:

        :param metrics:
            (required) List of metrics
        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param intervalInSecs:
            Sampling interval of stats
        '''
        return self._get('containers/{0}/stats/'.format(id), kwargs)

    def get_container_vdisks(self, id):
        '''get the list of vDisks of the specified container

        :param id:
            id of the container
        '''
        return self._get('containers/{0}/vdisks'.format(id))

    ############################################################
    # Disks
    ############################################################
    def get_disks(self, **kwargs):
        '''get the list of disks configured in the cluster

        Kwargs:

        :param count:
            number of disks to retrieve
        :param filterCriteria:
            filter criteria
        :param sortCriteria:
            sort criteria
        :param searchString:
            search string
        :param page:
            page number
        :param projection:
            projections on the attributes
        '''
        return self.get('disks/', kwargs)

    def get_disk_alerts(self, **kwargs):
        '''get the list of alerts generated on any disk

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of alerts
        :param resolved:
            Alerts which have been resolved
        :param acknowledged:
            Alerts which have been acknowledged
        :param severity:
            Alert severities
        :param alertTypeUuid:
            Alert type ids
        :param page:
            Page number
        '''
        return self._get('disks/alerts', kwargs)

    def get_disk_events(self, **kwargs):
        '''get the list of events generated on any disk

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of events
        :param acknowledged:
            Events which have been acknowledged
        :param page:
            Page number
        '''
        return self._get('disks/events', kwargs)

    def get_disk_health_check(self, **kwargs):
        '''get the health check summary for the disks

        Kwargs:

        :param filterCriteria:
            filter criteria
        :param detailedSummary:
            detailed summary
        '''
        return self._get('disks/health_check_summary', kwargs)

    def get_disk(self, id, **kwargs):
        '''get a disk with the specified id

        :param id:
            ID of the disk

        Kwargs:

        :param projection:
            projections on the attributes
        '''
        return self._get('disks/{0}'.format(id), kwargs)

    def delete_disk(self, id, **kwargs):
        '''mark specified disk for removal

        :param id:
            ID of the disk

        Kwargs:

        :param force:
            force the operation (ignores all system validations)
        '''
        return self._delete('disks/{0}'.format(id), kwargs)

    def get_disk_alerts(self, id, **kwargs):
        '''get the list of alerts generated on any disk

        :param id:
            id of the disk

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of alerts
        :param resolved:
            Alerts which have been resolved
        :param acknowledged:
            Alerts which have been acknowledged
        :param severity:
            Alert severities
        :param alertTypeUuid:
            Alert type ids
        :param page:
            Page number
        '''
        return self._get('disks/{0}/alerts'.format(id), kwargs)

    def get_disk_events(self, id, **kwargs):
        '''get the list of events generated on any disk

        :param id:
            id of the disk

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of events
        :param acknowledged:
            Events which have been acknowledged
        :param page:
            Page number
        '''
        return self._get('disks/{0}/events'.format(id), kwargs)

    def get_disk_stats(self, id, **kwargs):
        '''get the stats for a specified disk

        :param id:
            id of the disk

        Kwargs:

        :param metrics:
            (required) List of metrics
        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param intervalInSecs:
            Sampling interval of stats
        '''
        return self._get('disks/{0}/stats/'.format(id), kwargs)

    ############################################################
    # Encryption
    ############################################################

    def get_encryption_status(self):
        '''get encryption status of the cluster
        '''
        return self._get('encryption/')

    def set_encryption(self, enable):
        '''enable or disable encryption on the cluster

        :param enable:
            enable encryption
        '''
        payload = {"value": enable}
        return self._post('encryption/enable', payload=payload)

    def get_cert_test_results(self, **kwargs):
        '''get recent certificate test results

        Kwargs:

        :param hostIds:
            list of host IDs
        :param kmsServerNames:
            list of key management server names
        '''
        return self._get('encryption/recent_certificate_test_results', kwargs)

    def rekey_disks(self, **kwargs):
        '''set new password for encryption capable disks

        Kwargs:

        :param array:
            list of disk ids on which rekey needs to be performed
        '''
        return self._post('encryption/rekey', kwargs)

    def test_encryption(self, node_ids, kms_names):
        '''test encryption configuration of the cluster

        :param node_ids:
            list of node IDs
        :param kms_names:
            list of key management server names
        '''
        payload = {"serverList": kms_names, "nodeIdList": node_ids}
        return self._post('encryption/test', payload=payload)

    ############################################################
    # Events
    ############################################################
    def get_events(self, **kwargs):
        '''get the list of events generated in the cluster

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of events
        :param acknowledged:
            Events which have been acknowledged
        :param page:
            Page number
        '''
        return self._get('events/', kwargs)

    def acknowledge_events(self, **kwargs):
        '''acknowledge events using a filter criteria

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param severity:
            Severity
        :param entityType:
            Entity type
        :param entityTypeIds:
            Entity type IDs
        :param count:
            Maximum number of events
        '''
        return self._post('events/acknowledge', kwargs)

    def get_hardware_events(self, **kwargs):
        '''get the list of hardware events generated in the cluster

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of events
        :param acknowledged:
            Events which have been acknowledged
        :param page:
            Page number
        '''
        return self._get('events/hardware', kwargs)

    def get_storage_events(self, **kwargs):
        '''get the list of storage events generated in the cluster

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of events
        :param acknowledged:
            Events which have been acknowledged
        :param page:
            Page number
        '''
        return self._get('events/storage', kwargs)

    def acknowledge_event(self, id):
        '''acknowledge event with the specified ID

        :param id:
            Event ID
        '''
        return self._put('events/{0}/acknowledge'.format(id))

    ############################################################
    # Health Checks
    ############################################################
    def get_health_checks(self):
        '''get the list of health checks configured in the cluster
        '''
        return self._get('health_checks/')

    def update_health_checks(self, payload):
        '''update health check details

        :param payload:
            json health check instance
        '''
        return self._put('health_checks/', payload=payload)

    def get_health_check(self, id):
        '''get the health check with the specified ID

        :param id:
            ID of the health check
        '''
        return self._get('health_checks/{0}'.format(id))

    ############################################################
    # Hosts
    ############################################################
    def get_hosts(self, **kwargs):
        '''get the list of physical hosts configured in the cluster

        Kwargs:

        :param count:
            number of physical hosts to retrieve
        :param filterCriteria:
            filter criteria
        :param sortCriteria:
            sort criteria
        :param searchString:
            search string
        :param page:
            page number
        :param projection:
            projections on the attributes
        '''
        return self._get('hosts/', kwargs)

    def get_host_alerts(self, **kwargs):
        '''get the list of alerts generated on any host

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of alerts
        :param resolved:
            Alerts which have been resolved
        :param acknowledged:
            Alerts which have been acknowledged
        :param severity:
            Alert severities
        :param alertTypeUuid:
            Alert type ids
        :param page:
            Page number
        '''
        return self._get('hosts/alerts', kwargs)

    def get_host_events(self, **kwargs):
        '''get the list of events generated on any host

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of events
        :param acknowledged:
            Events which have been acknowledged
        :param page:
            Page number
        '''
        return self._get('hosts/events', kwargs)

    def get_host_health_check(self, **kwargs):
        '''get the health check summary for the hosts

        Kwargs:

        :param filterCriteria:
            filter criteria
        :param detailedSummary:
            detailed summary
        '''
        return self._get('hosts/health_check_summary', kwargs)

    def get_host_alerts(self, svm_id, **kwargs):
        '''get the list of alerts generated on any host

        :param svm_id:
            service VM ID

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of alerts
        :param resolved:
            Alerts which have been resolved
        :param acknowledged:
            Alerts which have been acknowledged
        :param severity:
            Alert severities
        :param alertTypeUuid:
            Alert type ids
        :param page:
            Page number
        '''
        return self._get('hosts/{0}/alerts'.format(svm_id), kwargs)

    def get_disk_events(self, svm_id, **kwargs):
        '''get the list of events generated on any host

        :param svm_id:
            service VM ID

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of events
        :param acknowledged:
            Events which have been acknowledged
        :param page:
            Page number
        '''
        return self._get('hosts/{0}/events'.format(svm_id), kwargs)

    def get_host_stats(self, svm_id, **kwargs):
        '''get the stats for a specified host

        :param svm_id:
            service VM ID

        Kwargs:

        :param metrics:
            (required) List of metrics
        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param intervalInSecs:
            Sampling interval of stats
        '''
        return self._get('hosts/{0}/stats/'.format(svm_id), kwargs)

    ############################################################
    # HTTP Proxies
    ############################################################
    def get_http_proxies(self):
        '''get the list of HTTP proxies configured in the cluster
        '''
        return self._get('http_proxies/')

    def add_http_proxy(self, address, username=None, password=None):
        '''add an HTTP proxy to the cluster

        :param address:
            proxy address
        :param username:
            proxy username
        :param password:
            proxy password
        '''
        payload = {"address": address,
                   "username": username,
                   "password": password}
        self._post('http_proxies/', payload=payload)

    def update_http_proxy(self, payload):
        '''update an HTTP proxy

        :param payload:
            json HTTP proxy configuration
        '''
        return self._put('http_proxies/', payload=payload)

    def get_http_proxy(self, name):
        '''get an HTTP proxy with the specified name

        :param name:
            name of an HTTP proxy
        '''
        return self._get('http_proxies/{0}'.format(name))

    def delete_http_proxy(self, name):
        '''delete an HTTP proxy with the specified name

        :param name:
            name of an HTTP proxy
        '''
        return self._delete('http_proxies/{0}'.format(name))

    ############################################################
    # Key Management Servers
    ############################################################
    def get_kms(self):
        '''get all key management servers from cluster
        '''
        return self._get('key_management_servers/')

    def add_kms(self, payload):
        '''add key management server to the cluster

        :param payload:
            json key management server configuration
        '''
        return self._post('key_management_servers/', payload=payload)

    def update_kms(self, payload):
        '''update the key management server configuration

        :param payload:
            json key management server configuration
        '''
        return self._put('key_management_server/', payload=payload)

    def get_kms(self, name):
        '''get key management server with the specified name

        :param name:
            key management server name
        '''
        return self._get('key_management_server/{0}'.format(name))

    def delete_kms(self, name):
        '''delete key management server with the specified name

        :param name:
            key management server name
        '''
        return self._delete('key_management_server/{0}'.format(name))

    ############################################################
    # License
    ############################################################
    def get_license(self):
        '''get current license file from the cluster
        '''
        return self._get('license/')

    def add_license(self, license_file):
        '''apply license file to the cluster

        :param cert:
            file object of license, rb mode
        :type cert: ``file``

        '''
        files = {'file': license}
        return self._post('license/', files=files)

    def get_license_alerts(self, **kwargs):
        '''get the list of alerts generated for any license

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of alerts
        :param resolved:
            Alerts which have been resolved
        :param acknowledged:
            Alerts which have been acknowledged
        :param severity:
            Alert severities
        :param alertTypeUuid:
            Alert type ids
        :param page:
            Page number
        :param entityType:
            Entity type
        :param entityIds:
            Entity ids
        '''
        return self._get('license/alerts/', kwargs)

    def get_license_allowances(self):
        '''show allowances for all features
        '''
        return self._get('license/allowances')

    def get_license_feature(self, feature_name):
        '''show allowances for a particular feature

        :param feature_name:
            name of the feature
        '''
        return self._get('license/allowances/{0}'.format(feature_name))

    def get_cluster_license_info(self):
        '''get cluster license info
        '''
        return self._get('license/cluster_info')

    def get_csf(self):
        '''get cluster summary file
        '''
        return self._get('license/cluster_summary_file')

    def get_license_events(self, **kwargs):
        '''get the list of events generated for any license

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of events
        :param acknowledged:
            Events which have been acknowledged
        :param page:
            Page number
        '''
        return self._get('license/events', kwargs)

    ############################################################
    # Protection Domains
    ############################################################
    def get_protection_domains(self, **kwargs):
        '''get the list of protection domains configured in the cluster

        Kwargs:

        :param names:
            protection domain names
        :param metroAvail:
            metro availability protection domain
        :param vStoreName:
            vStore name
        :param remoteSiteName:
            remote site name
        :param includeDeleted:
            include deleted
        :param projection:
            projections on the attributes
        '''
        return self._get('protection_domains/', kwargs)

    def add_protection_domain(self, payload):
        '''add a protection domain to be used for disaster recovery and backups

        :param payload:
            json protection domain configuration
        '''
        return self._post('protection_domains/', payload=payload)

    def get_protection_domain_alerts(self, **kwargs):
        '''get the list of alerts generated on any protection domain

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of alerts
        :param resolved:
            Alerts which have been resolved
        :param acknowledged:
            Alerts which have been acknowledged
        :param severity:
            Alert severities
        :param alertTypeUuid:
            Alert type ids
        :param page:
            Page number
        :param entityType:
            Entity type
        :param entityIds:
            Entity ids
        '''
        return self._get('protection_domains/alerts', kwargs)

    def get_consistency_groups(self, **kwargs):
        '''get the list of consistency groups in the cluster

        Kwargs:

        :param protectionDomains:
            protection domain names
        :param consistencyGroups:
            consistency group names
        :param includeDeleted:
            include deleted
        '''
        return self._get('protection_domains/consistency_groups/', kwargs)

    def get_dr_snapshots(self, **kwargs):
        '''get the list of snapshots created in protection domains

        Kwargs:

        :param count:
            number of DR snapshots to retrieve
        :param filterCriteria:
            filter criteria
        :param sortCriteria:
            sort criteria
        :param fullDetails:
            whether to include CG/VM details
        '''
        return self._get('consistency_groups/dr_snapshots/', kwargs)

    def get_protection_domain_events(self, **kwargs):
        '''get the list of events generated on any protection domain

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of events
        :param acknowledged:
            Events which have been acknowledged
        :param page:
            Page number
        '''
        return self._get('protection_domain/events', kwargs)

    def get_protection_domain_health(self, **kwargs):
        '''get the health check summary for the protection domain

        Kwargs:

        :param filterCriteria:
            filter criteria
        :param detailedSummary:
            detailed summary
        '''
        return self._get('protection_domains/health_check_summary', kwargs)

    def get_oob_schedules(self, **kwargs):
        '''get the list of out-of-band schedules in protection domains configured in the cluster

        Kwargs:

        :param protectionDomainNames:
            names of protection domains
        '''
        return self._get('protectoin_domains/oob_schedules/', kwargs)

    def get_pending_actions(self, **kwargs):
        '''get the list of pending actions in the cluster

        Kwargs:

        :param protectionDomainNames:
            names of protection domains
        '''
        return self._get('protection_domains/pending_actions/', kwargs)

    def get_pending_replications(self, **kwargs):
        '''get the list of pending replications in the cluster

        Kwargs:

        :param protectionDomainNames:
            protection domain names
        :param remoteSiteNames:
            remote site names
        '''
        return self._get('protection_domains/pending_replications/', kwargs)

    def get_replications(self, **kwargs):
        '''get the list of replications in the cluster

        Kwargs:

        :param protectionDomainNames:
            protection domain names
        :param remoteSiteNames:
            remote site names
        '''
        return self._get('protection_domains/replications/', kwargs)

    def get_protection_domain_status(self):
        '''get the data protection status for all protection domains
        '''
        return self._get('protection_domains/status')

    def get_unprotected_vms(self, **kwargs):
        '''get list of unprotected VMs in a cluster that can participate in Nutanix native backup and DR

        Kwargs:

        :param hostIds:
            host IDs
        :param vmNames:
            VM names
        :param containerNames:
            container names
        '''
        return self._get('protection_domains/unprotected_vms/', kwargs)

    def get_protection_domain(self, name, **kwargs):
        '''get a protection domain with the specified name

        :param name:
            name of the protection domain

        Kwargs:

        :param metroAvail:
            whether to include only metro availability related protection domains
        :param vStoreName:
            vStore name
        :param remoteSiteName:
            remote site name
        :param projection:
            projections on the attributes
        '''
        return self._get('protection_domains/{0}'.format(name), kwargs)

    def delete_protection_domain(self, name, **kwargs):
        '''mark a protection domain for removal
        Protection domain will be removed from the cluster when all outstanding
        operations on it are cancelled

        :param name:
            name of the protection domain

        Kwargs:

        :param skipRemoteCheck:
            skip checking remote protection domain
        '''
        return self._delete('protection_domains/{0}'.format(name), kwargs)

    def activate_protection_domain(self, name):
        '''activate a protection domain with the specified name

        :param name:
            name of the protection domain
        '''
        return self._post('protection_domains/{0}/activate'.format(name))

    def get_protection_domain_alerts(self, name, **kwargs):
        '''get the list of alerts generated on a specified protection domain

        :param name:
            name of the protection domain

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of alerts
        :param resolved:
            Alerts which have been resolved
        :param acknowledged:
            Alerts which have been acknowledged
        :param severity:
            Alert severities
        :param alertTypeUuid:
            Alert type ids
        :param page:
            Page number
        :param entityType:
            Entity type
        :param entityIds:
            Entity ids
        '''
        return self._get('protection_domains/{0}/alerts'.format(name), kwargs)

    def get_consistency_groups(self, name):
        '''get list of consistency groups in a specified protection domain

        :param name:
            name of the protection domain
        '''
        return self._get('protection_domains/{0}/consistency_groups/'.format(name))

    def deactivate_protection_domain(self, name):
        '''deactivate a protection domain with the specified name
        
        :param name:
            name of the protection domain
        '''
        return self._post('protection_domains/{0}/deactivate'.format(name))

    def get_dr_snapshots(self, name, **kwargs):
        '''get the list of snapshots created in a specified protection domain

        :param name:
            name of the protection domain

        Kwargs:

        :param count:
            number of DR snapshots to retrieve
        :param filterCriteria:
            filter criteria
        :param sortCriteria:
            sort criteria
        :param fullDetails:
            whether to include CG/VM details
        '''
        return self._get('protection_domains/{0}/dr_snapshots/'.format(name), kwargs)

    def get_protection_domain_events(self, name, **kwargs):
        '''get the list of events generated on a specified protection domain

        :param name:
            name of the protection domain

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of events
        :param acknowledged:
            Events which have been acknowledged
        :param page:
            Page number
        '''
        return self._get('protection_domain/{0}/events'.format(name), kwargs)

    def migrate_protection_domain(self, name):
        '''mark the specified protection domain as inactive and failover to the given remote site

        :param name:
            name of the protection domain
        '''
        return self._post('protection_domains/{0}/migrate'.format(name))

    def add_oob_schedule(self, name, payload):
        '''add an out of band snapshot schedule in the specified protection domain

        :param name:
            name of the protection domain
        :param payload:
            json out of band snapshot schedule configuration
        '''
        return self._post('protection_domains/{0}/oob_schedules'.format(name), kwargs)

    def get_oob_schedules(self, name):
        '''get the list of out of band schedules in the specified protection domain

        :param name:
            name of the protection domain
        '''
        return self._get('protection_domains/{0}/oob_schedules'.format(name))

    def delete_oob_schedule(self, pd_name, shedule_id):
        '''delete an out of band schedule

        :param pd_name:
            name of the protection domain
        :param schedule_id:
            ID of the out of band schedule
        '''
        return self._delete('protection_domains/{0}/oob_schedules/{1}'.format(pd_name, schedule_id))

    def get_pending_actions(self, name):
        '''get list of pending actions in the specified protection domain

        :param name:
            name of the protection domain
        '''
        return self._get('protection_domains/{0}/pending_actions/'.format(name))

    def get_pending_replications(self, name, **kwargs):
        '''get list of pending replications in the specified protection domain

        :param name:
            name of the protection domain

        Kwargs:

        :param remoteSiteNames:
            names of remote sites
        '''
        return self._get('protection_domains/{0}/pending_replications'.format(name), kwargs)

    def protect_vms(self, name, payload):
        '''add VMs to a protection domain to enable backup and disaster recovery

        :param name:
            name of the protection domain
        :param payload:
            json vm protection configuration
        '''
        return self._post('protection_domains/{0}/protect_vms'.format(name), payload=payload)

    def get_replications(self, name):
        '''get list of replications in a protection domain

        :param name:
            name of protection domain
        '''
        return self._get('protection_domains/{0}/replications/'.format(name))

    def restore_entities(self, name, payload):
        '''rollback VMs and/or NFS files in a protection domain to a given snapshot

        :param name:
            name of the protection domain
        :param payload:
            json restore configuration
        '''
        return self._post('protection_domains/{0}/restore_entities'.format(name), payload=payload)

    def rollback(self, pd_name, snapshot_id):
        '''rollback the specified protection domain to a given snapshot

        :param pd_name:
            name of the protection domain
        :param snapshot_id:
            ID of the snapshot
        '''
        payload = {"value": snapshot_id}
        return self._post('protection_domains/{0}/rollback'.format(name), payload=payload)

    def add_snapshot_schedule(self, name, payload):
        '''add a snapshot schedule to the specified protection domain

        :param name:
            name of the protection domains
        :param payload:
            json snapshot schedule configuration
        '''
        return self._post('protection_domains/{0}/schedules'.format(name), payload=payload)

    def get_snapshot_schedules(self, name):
        '''retrieve all snapshot schedules from the specified protection domain
        '''
        return self._get('protection_domains/{0}/schedules'.format(name))

    def get_protection_domain_stats(self, name, **kwargs):
        '''get the status for a specified protection domain
        If start time and end time are included in the query string,
        then historical stats are retrieved. Otherwise, the latest
        stats are retrieved.

        :param name:
            name of the protection domain

        Kwargs:

        :param metrics:
            (required) list of metrics
        :param startTimeInUsecs:
            start time in microseconds
        :param endTimeInUsecs:
            end time in microseconds
        :param intervalInSecs:
            sampling interval of stats
        '''
        return self._get('protection_domains/{0}/stats/'.format(name), kwargs)

    def unprotect_vms(self, name, **kwargs):
        '''remove VMs from a protection domain

        :param name:
            name of the protection domain

        Kwargs:

        :param array:
            (required) list of VMs
        '''
        return self._post('protection_domains/{0}/unprotect_vms'.format(name), kwargs)

    def update_replication_timeout(self, name, payload):
        '''update metro availability timeout for a specific protection domain

        :param name:
            name of the protection domain
        :param payload:
            json replication timeout configuration
        '''
        return self._put('protection_domains/{0}/break_replication_timeout'.format(name), payload=payload)

    def demote_protection_domain(self, name, **kwargs):
        '''demotes to standby metro availability role for a specified protection domain

        :param name:
            name of the protection domain

        Kwargs:

        :param skipRemoteCheck:
            skip checking remote protection domain
        '''
        return self._post('protection_domains/{0}/demote'.format(name), kwargs)

    def disable_metro_availability(self, name, **kwargs):
        '''disable metro availability for a specified protection domain

        :param name:
            name of the protection domain

        Kwargs:

        :param skipRemoteCheck:
            skip checking remote protection domain
        '''
        return self._post('protection_domains/{0}/metro_avail_disable'.format(name), kwargs)

    def enable_metro_availability(self, name, payload, **kwargs):
        '''enable metro availability for a specific protection domain based on vStore and remote site

        :param name:
            name of the protection domain
        :param payload:
            vStore and remote site configuration

        Kwargs:

        :param reEnable:
            re-enable operation
        :param skipRemoteCheck:
            skip checking remote protection domain
        :param force:
            skip checking remote container emptiness
        '''
        return self._post('protection_domains/{0}/metro_avail_enable'.format(name), kwargs, payload=payload)

    def promote_protection_domain(self, name, **kwargs):
        '''promotes to active metro availability role for a specified protection domain

        :param name:
            name of the protection domain

        Kwargs:

        :param skipRemoteCheck:
            skip checking remote protection domain
        '''
        return self._post('protection_domains/{0}/promote'.format(name), kwargs)

    def delete_snapshot_schedules(self, name):
        '''remove all snapshot schedules from the specified protection domain

        :param name:
            name of the protection domain
        '''
        return self._delete('protection_domains/{0}/schedules'.format(name))

    def delete_snapshot_schedule(self, pd_name, schedule_id):
        '''remove a snapshot schedule from the specified protection domain

        :param pd_name:
            name of the protection domain
        :param schedule_id:
            ID of the snapshot schedule
        '''
        return self._delete('protection_domains/{0}/schedules/{1}'.format(pd_name, schedule_id))

    def update_snapshot_schedule(self, pd_name, schedule_id, payload):
        '''replace a snapshot schedule from the specified protection domain

        :param pd_name:
            name of the protection domain
        :param schedule_id:
            ID of the snapshot schedule
        :param payload:
            json snapshot schedule configuration
        '''
        return self._put('protection_domains/{0}/schedules/{1}'.format(pd_name, schedule_id), payload=payload)

    def set_retention_policies(self, pd_name, schedule_id, payload):
        '''set retention policies of specified snapshot schedule from the specified protection domain

        :param pd_name:
            name of the protection domain
        :param schedule_id:
            ID of the snapshot schedule
        :param payload:
            json snapshot schedule configuration
        '''
        return self._post('protection_domains/{0}/schedules/{1}/retention_policies'.format(pd_name, schedule_id), payload=payload)

    def clear_retention_policies(self, pd_name, schedule_id):
        '''clear retention policies of specified snapshot schedule from the specified protection domain

        :param pd_name:
            name of the protection domain
        :param schedule_id:
            ID of the snapshot schedule
        '''
        return self._delete('protection_domains/{0}/schedules/{1}/retention_policies'.format(pd_name, schedule_id))

    def delete_snapshot(self, pd_name, snapshot_id):
        '''delete a snapshot of a protection domain

        :param pd_name:
            name of the protection domain
        :param snapshot_id:
            ID of the snapshot
        '''
        return self._delete('protection_domains/{0}/dr_snapshots/{1}'.format(pd_name, snapshot_id))

    def retain_snapshot(self, pd_name, snapshot_id, retention_time):
        '''retain a snapshot of a protection domain

        :param pd_name:
            name of the protection domain
        :param snapshot_id:
            ID of the snapshot
        :param retention_time:
            retention time in microseconds
        '''
        payload = {"value": retention_time}
        return self._post('protection_domains/{0}/dr_snapshots/{1}'.format(pd_name, snapshot_id), payload=payload)

    def update_replication_status(self, pd_name, replication_id, payload):
        '''update the state of the replication in a protection domain

        :param pd_name:
            name of the protection domain
        :param replication_id:
            ID of the replication
        :param payload:
            json of updated replication status (pause, resume, abort)
        '''
        return self._put('protection_domains/{0}/replications/{1}'.format(pd_name, replication_id), payload=payload)

    def abort_replication(self, pd_name, replication_id):
        '''abort a replication in a protection domain

        :param pd_name:
            name of the protection domain
        :type pd_name: ``str``
        :param replication_id:
            ID of the replication
        :type replication_id: ``str``
        '''
        return self._delete('protection_domains/{0}/replications/{1}'.format(pd_name, replication_id))

    ############################################################
    # Pulse
    #   * Not implemented in API
    ############################################################

    ############################################################
    # Remote Sites
    ############################################################
    def get_remote_sites(self, **kwargs):
        '''get the list of remote sites configured in the cluster
        
        Kwargs:

        :param names:
            remote site names
        :param metroCompatible:
            remote site stretchable
        :param fullDetails:
            remote cluster full detail
        :param includeDeleted:
            include deleted
        :param projection:
            projections on the attributes
        '''
        return self._get('remote_sites/', kwargs)

    def add_remote_site(self, payload):
        '''add a remote site

        :param payload:
            json remote site configuration
        '''
        return self._post('remote_sites/', payload=payload)

    def update_remote_site(self, payload):
        '''update a remote site

        :param payload:
            json remote site configuration
        '''
        return self._put('remote_sites/', payload=payload)

    def get_remote_sites_alerts(self, **kwargs):
        '''get the list of alerts generated on any remote site

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of alerts
        :param resolved:
            Alerts which have been resolved
        :param acknowledged:
            Alerts which have been acknowledged
        :param severity:
            Alert severities
        :param alertTypeUuid:
            Alert type ids
        :param page:
            Page number
        :param entityType:
            Entity type
        :param entityIds:
            Entity ids
        '''
        return self._get('remote_sites/alerts', kwargs)

    def get_remote_sites_snapshots(self, **kwargs):
        '''get the list of all snapshots created in remote sites

        Kwargs:

        :param count:
            maximum number of DR snapshots to retrieve
        :param filterCriteria:
            filter criteria
        :param sortCriteria:
            sort criteria
        :param fullDetails:
            whether to include consistency group/VM details
        '''
        return self._get('remote_sites/dr_snapshots', kwargs)

    def get_remote_sites_events(self, **kwargs):
        '''get the list of events generated on any remote site

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of events
        :param acknowledged:
            Events which have been acknowledged
        :param page:
            Page number
        '''
        return self._get('remote_sites/events', kwargs)

    def get_remote_sites_health(self, **kwargs):
        '''get the health check summary for the remote sites

        Kwargs:

        :param filterCriteria:
            filter criteria
        :param detailedSummary:
            detailed summary
        '''
        return self._get('remote_sites/health_check_summary', kwargs)

    def get_pending_remote_replications(self, **kwargs):
        '''get all pending replications on the cluster

        Kwargs:

        :param protectionDomainNames:
            protection domain names
        :param remoteSiteNames:
            remote site names
        '''
        return self._get('remote_sites/pending_replications/', kwargs)

    def get_remote_site(self, name, **kwargs):
        '''get a remote site with the specified name

        :param name:
            name of the remote site

        Kwargs:

        :param projection:
            projections on the attributes
        '''
        return self._get('remote_sites/{0}'.format(name), kwargs)

    def delete_remote_site(self, name):
        '''delete a remote site with the specified name from the cluster

        :param name:
            name of the remote site
        '''
        return self._delete('remote_sites/{0}'.format(name))

    def get_remote_site_alerts(self, name, **kwargs):
        '''get the list of alerts generated on a specified remote site

        :param name:
            name of the remote site

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of alerts
        :param resolved:
            Alerts which have been resolved
        :param acknowledged:
            Alerts which have been acknowledged
        :param severity:
            Alert severities
        :param alertTypeUuid:
            Alert type ids
        :param page:
            Page number
        :param entityType:
            Entity type
        :param entityIds:
            Entity ids
        '''
        return self._get('remote_sites/{0}/alerts'.format(name), kwargs)

    def get_remote_site_snapshots(self, name, **kwargs):
        '''get the list of snapshots created in a particular remote site

        :param name:
            name of the remote site

        Kwargs:

        :param count:
            maximum number of DR snapshots to retrieve
        :param filterCriteria:
            filter criteria
        :param sortCriteria:
            sort criteria
        :param fullDetails:
            whether to include consistency group/VM details
        '''
        return self._get('remote_sites/{0}/dr_snapshots/'.format(name), kwargs)

    def get_remote_site_events(self, name, **kwargs):
        '''get the list of events generated on a specified remote site

        :param name:
            name of the remote site

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of events
        :param acknowledged:
            Events which have been acknowledged
        :param page:
            Page number
        '''
        return self._get('remote_sites/{0}/events'.format(name), kwargs)

    def get_pending_remote_replications(self, name, **kwargs):
        '''get all pending replications on the cluster

        :param name:
            name of the remote site

        Kwargs:

        :param protectionDomainNames:
            protection domain names
        :param remoteSiteNames:
            remote site names
        '''
        return self._get('remote_sites/{0}/pending_replications/'.format(name), kwargs)

    def get_remote_site_stats(self, name, **kwargs):
        '''get the stats for a specified remote site
        If start time and end time are included in the query string,
        then historical stats are retrieved. Otherwise, the latest
        stats are retrieved.

        :param name:
            name of the remote site

        Kwargs:

        :param metrics:
            (required) list of metrics
        :param startTimeInUsecs:
            start time in microseconds
        :param endTimeInUsecs:
            end time in microseconds
        :param intervalInSecs:
            sampling interval of stats
        '''
        return self._get('remote_stats/{0}/stats/'.format(name), kwargs)

    ############################################################
    # SMB Server
    ############################################################
    def get_smb_config(self):
        '''retrieves SMB server configuration settings for the cluster
        '''
        return self._get('smb_server/configuration')

    def manage_kerberos(self, payload):
        '''manages enabling/disabling Kerberos security for the cluster

        :param payload:
            json kerberos configuration
        '''
        return self._put('smb_server/kerberos', payload=payload)

    ############################################################
    # SNMP
    ############################################################
    def get_snmp_config(self):
        '''get the complete SNMP configuration including users,
        transports, and traps configured in the cluster
        '''
        return self._get('snmp/')

    def add_snmp_transports(self, **kwargs):
        '''add SNMP transports to the existing SNMP transports

        Kwargs:

        :param transports:
            list of SNMP transports
        '''
        return self._post('snmp/add_transports', kwargs)

    def remove_snmp_transports(self, **kwargs):
        '''remove SNMP transports to the existing SNMP transports

        Kwargs:

        :param transports:
            list of SNMP transports
        '''
        return self._post('snmp/remove_transports', kwargs)

    def enable_snmp(self, enable):
        '''enable/disable SNMP configuration in the cluster

        :param enable:
            enable/disable SNMP
        :type enable: ``boolean``
        '''
        payload = {"value": enable}
        return self._put('snmp/status', payload=payload)

    def get_snmp_status(self):
        '''get the SNMP status
        '''
        return self._get('snmp/status')

    def get_snmp_transports(self):
        '''get the list of SNMP transports configured in the cluster
        '''
        return self._get('snmp/transports')

    def get_snmp_traps(self):
        '''get the list of SNMP traps configured in the cluster
        '''
        return self._get('snmp/traps')

    def update_snmp_trap(self, payload):
        '''edit the specified SNMP trap

        :param payload:
            json snmp trap configuration
        '''
        return self._put('snmp/traps', payload=payload)

    def add_snmp_trap(self, payload):
        '''add SNMP trap to the cluster

        :param payload:
            json snmp trap configuration
        '''
        return self._post('snmp/traps', payload=payload)

    def delete_snmp_trap(self, address):
        '''delete SNMP trap with the specified address

        :param address:
            address of SNMP trap
        :type address: ``str``
        '''
        return self._delete('snmp/traps/{0}'.format(address))

    def get_snmp_trap(self, address):
        '''get SNMP trap with the specified address

        :param address:
            address of SNMP trap
        :type address: ``str``
        '''
        return self._get('snmp/traps/{0}'.format(address))

    def add_snmp_user(self, payload):
        '''add SNMP user to the cluster

        :param payload:
            json snmp user configuration
        '''
        return self._post('snmp/users', payload=payload)

    def update_snmp_user(self, payload):
        '''edit SNMP user to the cluster

        :param payload:
            json snmp user configuration
        '''
        return self._put('snmp/users', payload=payload)

    def get_snmp_user(self):
        '''get the list of SNMP users configured in the cluster
        '''
        return self._get('snmp/users')

    def delete_snmp_user(self, address):
        '''delete SNMP user with the specified username

        :param username:
            name of SNMP user
        :type username: ``str``
        '''
        return self._delete('snmp/users/{0}'.format(username))

    def get_snmp_user(self, address):
        '''get SNMP user with the specified username

        :param username:
            name of SNMP user
        :type username: ``str``
        '''
        return self._get('snmp/users/{0}'.format(username))

    ############################################################
    # Storage Pools
    ############################################################
    def get_storage_pools(self, **kwargs):
        '''get the list of storage pools configured in the cluster

        Kwargs:

        :param count:
            number of clusters to retrieve
        :param filterCriteria:
            filter criteria
        :param sortCriteria:
            sort criteria
        :param searchString:
            search string
        :param page:
            page number
        :param projection:
            projections on the attributes
        '''
        return self._get('storage_pools/', kwargs)

    def add_storage_pool(self, payload, **kwargs):
        '''add a storage pool to the cluster

        :param payload:
            json storage pool configuration

        Kwargs:

        :param force:
            force the operation
        :type force: ``boolean``
        '''
        return self._post('storage_pools/', kwargs, payload=payload)

    def update_storage_pool(self, payload, **kwargs):
        '''update the specified storage pool

        :param payload:
            json storage pool configuration

        Kwargs:

        :param force:
            force the operation
        :type force: ``boolean``
        '''
        return self._put('storage_pools/', kwargs, payload=payload)

    def get_storage_pool_alerts(self, **kwargs):
        '''get the list of alerts generated on any storage pool

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :type startTimeInUsecs: ``int``
        :param endTimeInUsecs:
            End time in microseconds
        :type endTimeInUsecs: ``int``
        :param count:
            Maximum number of alerts
        :type count: ``int``
        :param resolved:
            Alerts which have been resolved
        :type resolved: ``boolean``
        :param acknowledged:
            Alerts which have been acknowledged
        :type acknowledged: ``boolean``
        :param severity:
            Alert severities
        :type severity: ``list``
        :param alertTypeUuid:
            Alert type ids
        :type alertTypeUuid: ``list``
        :param page:
            Page number
        :type page: ``int``
        '''
        return self._get('storage_pools/alerts/', kwargs)

    def get_storage_pool_events(self, **kwargs):
        '''get the list of events generated on any storage pool

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :type startTimeInUsecs: ``int``
        :param endTimeInUsecs:
            End time in microseconds
        :type endTimeInUsecs: ``int``
        :param count:
            Maximum number of alerts
        :type count: ``int``
        :param acknowledged:
            Alerts which have been acknowledged
        :type acknowledged: ``boolean``
        :param page:
            Page number
        :type page: ``int``
        '''
        return self._get('storage_pools/events/', kwargs)

    def get_storage_pool(self, id, **kwargs):
        '''get a storage pool with the specified ID

        :param id:
            ID of the storage pool

        Kwargs:

        :param count:
            number of clusters to retrieve
        :param filterCriteria:
            filter criteria
        :param sortCriteria:
            sort criteria
        :param searchString:
            search string
        :param page:
            page number
        :param projection:
            projections on the attributes
        '''
        return self._get('storage_pools/{0}'.format(id), kwargs)

    def delete_storage_pool(self, id):
        '''delete a storage pool with the specified ID

        :param id:
            ID of the storage pool
        '''
        return self._delete('storage_pools/{0}'.format(id))

    def get_storage_pool_alerts(self, id, **kwargs):
        '''get the list of alerts generated on a specified storage pool

        :param id:
            ID of a storage pool

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :type startTimeInUsecs: ``int``
        :param endTimeInUsecs:
            End time in microseconds
        :type endTimeInUsecs: ``int``
        :param count:
            Maximum number of alerts
        :type count: ``int``
        :param resolved:
            Alerts which have been resolved
        :type resolved: ``boolean``
        :param acknowledged:
            Alerts which have been acknowledged
        :type acknowledged: ``boolean``
        :param severity:
            Alert severities
        :type severity: ``list``
        :param alertTypeUuid:
            Alert type ids
        :type alertTypeUuid: ``list``
        :param page:
            Page number
        :type page: ``int``
        '''
        return self._get('storage_pools/{0}/alerts/'.format(id), kwargs)

    def get_storage_pool_events(self, id, **kwargs):
        '''get the list of events generated on a specified storage pool

        :param id:
            ID of a storage pool

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :type startTimeInUsecs: ``int``
        :param endTimeInUsecs:
            End time in microseconds
        :type endTimeInUsecs: ``int``
        :param count:
            Maximum number of alerts
        :type count: ``int``
        :param acknowledged:
            Alerts which have been acknowledged
        :type acknowledged: ``boolean``
        :param page:
            Page number
        :type page: ``int``
        '''
        return self._get('storage_pools/{0}/events/'.format(id), kwargs)

    def get_storage_pool_stats(self, id, **kwargs):
        '''get the stats for a specified storage pool

        :param id:
            ID of a storage pool

        Kwargs:

        :param metrics:
            (required) list of metrics
        :param startTimeInUsecs:
            start time in microseconds
        :param endTimeInUsecs:
            end time in microseconds
        :param intervalInSecs:
            sampling interval of stats
        '''
        return self._get('storage_pools/{0}/stats/'.format(id), kwargs)

    ############################################################
    # Upgrade
    #   * Not implemented in API
    ############################################################

    ############################################################
    # vDisks
    ############################################################
    def add_vdisk(self, payload):
        '''add a vDisk to the cluster

        :param payload:
            json vDisk configuration
        '''
        return self._post('vdisks/', payload=payload)

    def update_vdisk(self, payload):
        '''update a vDisk

        :param payload:
            json vDisk configuration
        '''
        return self._put('vdisks/', payload=payload)

    def get_vdisks(self, **kwargs):
        '''get the list of vDisks configured in the cluster

        Kwargs:

        :param includedeleted:
            include deleted vDisks
        :type includedeleted: ``boolean``
        :param vdiskNames:
            vDisk names
        :param projection:
            projections on the attributes
        '''
        return self._get('vdisks/', kwargs)

    def get_vdisk_alerts(self, **kwargs):
        '''get the list of alerts generated on any vDisk

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :type startTimeInUsecs: ``int``
        :param endTimeInUsecs:
            End time in microseconds
        :type endTimeInUsecs: ``int``
        :param count:
            Maximum number of alerts
        :type count: ``int``
        :param resolved:
            Alerts which have been resolved
        :type resolved: ``boolean``
        :param acknowledged:
            Alerts which have been acknowledged
        :type acknowledged: ``boolean``
        :param severity:
            Alert severities
        :type severity: ``list``
        :param alertTypeUuid:
            Alert type ids
        :type alertTypeUuid: ``list``
        :param page:
            Page number
        :type page: ``int``
        '''
        return self._get('vdisks/alerts', kwargs)

    def get_vdisk_events(self, **kwargs):
        '''get the list of events generated on any vDisk

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of events
        :param acknowledged:
            Events which have been acknowledged
        :param page:
            Page number
        '''
        return self._get('vdisks/events', kwargs)

    def get_snapshots(self):
        '''get the complete list of snapshots in the cluster
        '''
        return self._get('vdisks/snapshots/')

    def get_snapshots(self, name):
        '''get a snapshot with the specified name

        :param name:
            name of the snapshot
        :type name: ``str``
        '''
        return self._get('vdisks/snapshots/{0}/'.format(name))

    def get_vdisk(self, name, **kwargs):
        '''get a vdisk with the specified name

        :param name:
            name of the snapshot
        :type name: ``str``

        Kwargs:

        :param projection:
            projections on the attributes
        '''
        return self._get('vdisks/{0}'.format(name))

    def delete_vdisk(self, name):
        '''delete a vdisk with the specified name

        :param name:
            name of the snapshot
        :type name: ``str``
        '''
        return self._delete('vdisks/{0}'.format(name))

    def get_vdisk_alerts(self, name, **kwargs):
        '''get the list of alerts generated on any vDisk

        :param name:
            name of the vdisk
        :type name: ``str``

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :type startTimeInUsecs: ``int``
        :param endTimeInUsecs:
            End time in microseconds
        :type endTimeInUsecs: ``int``
        :param count:
            Maximum number of alerts
        :type count: ``int``
        :param resolved:
            Alerts which have been resolved
        :type resolved: ``boolean``
        :param acknowledged:
            Alerts which have been acknowledged
        :type acknowledged: ``boolean``
        :param severity:
            Alert severities
        :type severity: ``list``
        :param alertTypeUuid:
            Alert type ids
        :type alertTypeUuid: ``list``
        :param page:
            Page number
        :type page: ``int``
        '''
        return self._get('vdisks/{0}/alerts'.format(name), kwargs)

    def get_vdisk_events(self, name, **kwargs):
        '''get the list of events generated on any vDisk

        :param name:
            name of the vdisk
        :type name: ``str``

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of events
        :param acknowledged:
            Events which have been acknowledged
        :param page:
            Page number
        '''
        return self._get('vdisks/{0}/events'.format(name), kwargs)

    def create_snapshot(self, vdisk_name, snapshot_name):
        '''create a snapshot for the specified vDisk

        :param vdisk_name:
            name of the vdisk
        :type vdisk_name: ``str``
        :param snapshot_name:
            name of the snapshot
        :type snapshot_name: ``str``
        '''
        payload = {"value": snapshot_name}
        return self._post('vdisks/{0}/snapshots'.format(name), payload=payload)

    def get_snapshots(self, name):
        '''get the list of snapshots for the specified vDisk

        :param name:
            name of the vdisk
        :type name: ``str``
        '''
        return self._get('vdisks/{0}/snapshots/'.format(name))

    def get_vdisk_stats(self, name, **kwargs):
        '''get the stats for a specified vDisk

        :param name:
            name of the vDisk
        :type name: ``str``

        Kwargs:

        :param metrics:
            (required) list of metrics
        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param intervalInSecs:
            sampling interval of stats
        '''
        return self._get('vdisks/{0}/stats/'.format(name), kwargs)

    ############################################################
    # Virtual Disks
    ############################################################
    def get_virtual_disks(self, **kwargs):
        '''get the list of VirtualDisks configured in the cluster

        Kwargs:

        :param count:
            number of clusters to retrieve
        :param filterCriteria:
            filter criteria
        :param sortCriteria:
            sort criteria
        :param searchString:
            search string
        :param page:
            page number
        :param projection:
            projections on the attributes
        '''
        return self._get('virtual_disks/', kwargs)

    def get_virtual_disk(self, id, **kwargs):
        '''get the VirtualDisk with the specified ID

        :param id:
            id of the vDisk
        :type name: ``str``

        Kwargs:

        :param projection:
            projections on the attributes
        '''
        return self._get('virtual_disks/{0}'.format(name), kwargs)

    def get_virtual_disk_stats(self, id, **kwargs):
        '''get the stats for the specified VirtualDisk

        :param id:
            id of the vDisk
        :type name: ``str``

        Kwargs:

        :param metrics:
            (required) list of metrics
        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param intervalInSecs:
            sampling interval of stats
        '''
        return self._get('virtual_disks/{0}/stats'.format(name), kwargs)

    ############################################################
    # VMs
    ############################################################
    def get_vms(self, **kwargs):
        '''get the list of VMs configured in the cluster

        Kwargs:

        :param count:
            number of clusters to retrieve
        :param filterCriteria:
            filter criteria
        :param sortCriteria:
            sort criteria
        :param searchString:
            search string
        :param page:
            page number
        :param projection:
            projections on the attributes
        '''
        return self._get('vms/', kwargs)

    def get_vm_alerts(self, **kwargs):
        '''get the list of alerts generated on any VM

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :type startTimeInUsecs: ``int``
        :param endTimeInUsecs:
            End time in microseconds
        :type endTimeInUsecs: ``int``
        :param count:
            Maximum number of alerts
        :type count: ``int``
        :param resolved:
            Alerts which have been resolved
        :type resolved: ``boolean``
        :param acknowledged:
            Alerts which have been acknowledged
        :type acknowledged: ``boolean``
        :param severity:
            Alert severities
        :type severity: ``list``
        :param alertTypeUuid:
            Alert type ids
        :type alertTypeUuid: ``list``
        :param page:
            Page number
        :type page: ``int``
        '''
        return self._get('vms/alerts', kwargs)

    def get_vm_events(self, **kwargs):
        '''get the list of events generated on any VM

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of events
        :param acknowledged:
            Events which have been acknowledged
        :param page:
            Page number
        '''
        return self._get('vms/events', kwargs)

    def get_vm_health_check(self, **kwargs):
        '''get the health check summary for VMs

        Kwargs:

        :param filterCriteria:
            filter criteria
        :param detailedSummary:
            detailed summary
        '''
        return self._get('vms/health_check_summary', kwargs)

    def get_vm(self, id, **kwargs):
        '''get VM with the specified ID

        :param id:
            id of the vDisk
        :type name: ``str``

        Kwargs:

        :param projection:
            projections on the attributes
        '''
        return self._get('vms/{0}'.format(id), kwargs)

    def get_vm_alerts(self, id, **kwargs):
        '''get the list of alerts generated on any VM

        :param id:
            ID of the VM
        :type name: ``str``

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :type startTimeInUsecs: ``int``
        :param endTimeInUsecs:
            End time in microseconds
        :type endTimeInUsecs: ``int``
        :param count:
            Maximum number of alerts
        :type count: ``int``
        :param resolved:
            Alerts which have been resolved
        :type resolved: ``boolean``
        :param acknowledged:
            Alerts which have been acknowledged
        :type acknowledged: ``boolean``
        :param severity:
            Alert severities
        :type severity: ``list``
        :param alertTypeUuid:
            Alert type ids
        :type alertTypeUuid: ``list``
        :param page:
            Page number
        :type page: ``int``
        '''
        return self._get('vms/{0}/alerts'.format(id), kwargs)

    def get_vm_events(self, id, **kwargs):
        '''get the list of events generated on any VM

        :param id:
            ID of the VM
        :type name: ``str``

        Kwargs:

        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param count:
            Maximum number of events
        :param acknowledged:
            Events which have been acknowledged
        :param page:
            Page number
        '''
        return self._get('vms/{0}/events'.format(id), kwargs)

    def get_vm_stats(self, id, **kwargs):
        '''get the stats for a specified VM

        :param id:
            id of the vDisk
        :type name: ``str``

        Kwargs:

        :param metrics:
            (required) list of metrics
        :param startTimeInUsecs:
            Start time in microseconds
        :param endTimeInUsecs:
            End time in microseconds
        :param intervalInSecs:
            sampling interval of stats
        '''
        return self._get('vms/{0}/stats/'.format(id), kwargs)

    def get_vm_vdisks(self, vm_id):
        '''get the list of vDisks attached to the specified VM

        :param id:
            id of the vDisk
        :type name: ``str``
        '''
        return self._get('vms/{0}/vdisks'.format(vm_id))

    def get_vm_virtual_disks(self, vm_id, **kwargs):
        '''get the list of VirtualDisks attached to the specified VM

        :param vm_id:
            ID of the VM
        :type vm_id: ``str``

        Kwargs:

        :param sortCriteria:
            sort criteria
        :param projection:
            projections on the attributes
        '''
        return self._get('vms/{0}/virtual_disks'.format(vm_id), kwargs)

    ############################################################
    # vStores
    ############################################################
    def get_vstores(self, **kwargs):
        '''get the list of vStores configured in the cluster

        Kwargs:

        :param ids:
            vStore IDs
        :param names:
            vStore names
        :param includeDeleted:
            include deleted vStores
        '''
        return self._get('vstores/', kwargs)

    def get_vstore(self, id):
        '''get a vStore with the specified ID

        :param id:
            ID of the vStore
        :type id: ``str``
        '''
        return self._get('vstores/{0}'.format(id))

    def protect_vstore(self, id):
        '''protect a vStore with the specified ID

        :param id:
            ID of the vStore
        :type id: ``str``
        '''
        return self._post('vstores/{0}/protect')

    def unprotect_vstore(self, id):
        '''unprotect a vStore with the specified ID

        :param id:
            ID of the vStore
        :type id: ``str``
        '''
        return self._post('vstores/{0}/unprotect')

