"""DNS Authenticator for Azure DNS."""
import logging
import os

import zope.interface

from .cred_wrapper import CredentialWrapper
from azure.mgmt.dns import DnsManagementClient
from azure.common.client_factory import get_client_from_auth_file
from azure.mgmt.dns.models import RecordSet, TxtRecord
from msrestazure.azure_exceptions import CloudError


from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Azure DNS

    This Authenticator uses the Azure DNS API to fulfill a dns-01 challenge.
    """

    description = (
    'Obtain certificates using a DNS TXT record (if you are using Azure DNS '
    'for DNS).')
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add,
                                                       default_propagation_seconds=60)
        add('subscription',
            help=('Azure subscription ID in which the DNS zone is located'),
            default=None)
        add('resource-group',
            help=('Resource Group in which the DNS zone is located'),
            default=None)

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Azure DNS API.'

    def _setup_credentials(self):
        if self.conf('resource-group') is None:
            raise errors.PluginError('Please specify a resource group using '
                                     '--dns-azure-resource-group <RESOURCEGROUP>')

        if self.conf('subscription') is None:
            raise errors.PluginError(
                'Please specify a subscription ID'
                'using --dns-azure-subscription <SUBSCRIPTION-ID>')

    def _perform(self, domain, validation_name, validation):
        self._get_azure_client().add_txt_record(validation_name,
                                                validation,
                                                self.ttl)

    def _cleanup(self, domain, validation_name, validation):
        self._get_azure_client().del_txt_record(validation_name)

    def _get_azure_client(self):
        return _AzureClient(self.conf('resource-group'),
                            self.conf('subscription'))


class _AzureClient(object):
    """
    Encapsulates all communication with the Azure Cloud DNS API.
    """

    def __init__(self, resource_group, subscription_id=None):
        self.resource_group = resource_group
        credentials = CredentialWrapper()
        self.dns_client = DnsManagementClient(credentials, subscription_id)

    def get_existing_records(self, zone):
        """
        Returns the list of already existing txt-records
        """
        rs = self.dns_client.record_sets.list_by_type(self.resource_group, zone, "TXT").get(0)
        if len(rs) == 1:
            return rs[0].txt_records
        return []

    def add_txt_record(self, domain, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.

        :param str domain: The fqdn (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Azure API
        """
        try:
            zone = self._find_managed_zone(domain)
            relative_record_name = ".".join(
                domain.split('.')[0:-len(zone.split('.'))])
            txts = self.get_existing_records(zone)
            record = RecordSet(ttl=record_ttl,
                               txt_records=txts + [TxtRecord(value=[record_content])])
            self.dns_client.record_sets.create_or_update(self.resource_group,
                                                         zone,
                                                         relative_record_name,
                                                         'TXT',
                                                         record)
        except CloudError as e:
            logger.error('Encountered error adding TXT record: %s', e)
            raise errors.PluginError('Error communicating with the Azure DNS API: {0}'.format(e))

    def del_txt_record(self, domain):
        """
        Delete a TXT record using the supplied information.

        :param str domain: The fqdn (typically beginning with '_acme-challenge.').
        :raises certbot.errors.PluginError: if an error occurs communicating with the Azure API
        """

        try:
            zone = self._find_managed_zone(domain)
            relative_record_name = ".".join(
                domain.split('.')[0:-len(zone.split('.'))])
            self.dns_client.record_sets.delete(self.resource_group,
                                               zone,
                                               relative_record_name,
                                               'TXT')
        except (CloudError, errors.PluginError) as e:
            logger.warning('Encountered error deleting TXT record: %s', e)

    def _find_managed_zone(self, domain):
        """
        Find the managed zone for a given domain.

        :param str domain: The domain for which to find the managed zone.
        :returns: The name of the managed zone, if found.
        :rtype: str
        :raises certbot.errors.PluginError: if the managed zone cannot be found.
        """
        try:
            azure_zones = self.dns_client.zones.list()  # TODO - catch errors
            azure_zones_list = []
            while True:
                for zone in azure_zones.current_page:
                    azure_zones_list.append(zone.name)
                azure_zones.next()
        except StopIteration:
            pass
        except CloudError as e:
            logger.error('Error finding zone: %s', e)
            raise errors.PluginError('Error finding zone form the Azure DNS API: {0}'.format(e))
        zone_dns_name_guesses = dns_common.base_domain_name_guesses(domain)

        for zone_name in zone_dns_name_guesses:
            if zone_name in azure_zones_list:
                return zone_name

        raise errors.PluginError(
            'Unable to determine managed zone for {0} using zone names: {1}.'
            .format(domain, zone_dns_name_guesses))
