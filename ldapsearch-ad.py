#!/usr/bin/env python3

import argparse
import datetime
import ldap3
import logging
import re
import sys
import struct
import codecs


def c_red(message):
    """Color text for bad configuration."""
    return '\x1b[0;31;40m{}\x1b[0m'.format(message)


def c_green(message):
    """Color text for good configuration."""
    return '\x1b[0;32;40m{}\x1b[0m'.format(message)


def c_orange(message):
    """Color text for weak configuration."""
    return '\x1b[0;33;40m{}\x1b[0m'.format(message)


def c_blue(message):
    """Color text for information."""
    return '\x1b[0;34;40m{}\x1b[0m'.format(message)


def c_purple(message):
    """Color text for abnormal behavior of the tool itself."""
    return '\x1b[0;35;40m{}\x1b[0m'.format(message)


def c_cyan(message):
    """Mostly for general usefull information."""
    return '\x1b[0;36;40m{}\x1b[0m'.format(message)


def c_white_on_red(message):
    """Color text for very bad configuration."""
    return '\x1b[1;37;41m{}\x1b[0m'.format(message)


def log_title(title, level=2):
    heading = '#' * level
    logging.info('\x1b[1;37;40m{} {} {}\x1b[0m'.format(heading, title, heading))


def log_error(message):
    logging.error('{} {}'.format(c_red('[-]'), message))


def log_info(message):
    logging.info('{} {}'.format(c_blue('[+]'), message))


def log_success(message):
    logging.info('{} {}'.format(c_green('[*]'), message))


def str_human_date(date):
    # ldap3 version 2.6 returns a datetime.timedelta object
    if isinstance(date, datetime.timedelta):
        nb_sec = int(date.total_seconds())
    # older versions return a negative big number
    else:
        nb_sec = int((- date) / 10000000)
    if nb_sec > 60:
        nb_min = int(nb_sec / 60)
        nb_sec = nb_sec % 60
        if nb_min > 60:
            nb_hour = int(nb_min / 60)
            nb_min = nb_min % 60
            if nb_hour > 24:
                nb_day = int(nb_hour / 24)
                nb_hour = nb_hour % 24
                return '{} days, {} hours, {} minutes, {} secondes'.format(nb_day, nb_hour, nb_min, nb_sec)
            return '{} hours, {} minutes, {} secondes'.format(nb_hour, nb_min, nb_sec)
        return '{} minutes, {} secondes'.format(nb_min, nb_sec)
    return '{} secondes'.format(nb_sec)


def str_functionality_level(num):
    """Return the functionality level as described at:
    https://msdn.microsoft.com/en-us/library/cc223274.aspx
    Note: it is the same for forest, domain, and domain controller."""
    n = int(num)
    func_levels = [
        c_white_on_red('Windows 2000'),
        c_white_on_red('Windows 2003 with mixed domains'),
        c_white_on_red('Windows 2003'),
        c_red('Windows 2008'),
        c_red('Windows 2008 R2'),
        c_orange('Windows 2012'),
        c_orange('Windows 2012 R2'),
        c_green('Windows 2016')
        ]
    if 0 <= n < len(func_levels):
        return func_levels[n]
    else:
        return 'Not known, update this script. (value = {})'.format(num)


def list_uac_flags(uac):
    """Return a list of property flags as described at:
    https://support.microsoft.com/en-gb/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro"""
    flags = []
    if uac & 0x1 > 0:
        flags.append('SCRIPT')
    if uac & 0x2 > 0:
        flags.append('ACCOUNTDISABLE')
    if uac & 0x8 > 0:
        flags.append('HOMEDIR_REQUIRED')
    if uac & 0x10 > 0:
        flags.append('LOCKOUT')
    if uac & 0x20 > 0:
        flags.append('PASSWD_NOTREQD')
    if uac & 0x40 > 0:
        flags.append('PASSWD_CANT_CHANGE')
    if uac & 0x80 > 0:
        flags.append('ENCRYPTED_TEXT_PWD_ALLOWED')
    if uac & 0x100 > 0:
        flags.append('TEMP_DUPLICATE_ACCOUNT')
    if uac & 0x200 > 0:
        flags.append('NORMAL_ACCOUNT')
    if uac & 0x800 > 0:
        flags.append('INTERDOMAIN_TRUST_ACCOUNT')
    if uac & 0x1000 > 0:
        flags.append('WORKSTATION_TRUST_ACCOUNT')
    if uac & 0x2000 > 0:
        flags.append('SERVER_TRUST_ACCOUNT')
    if uac & 0x10000 > 0:
        flags.append('DONT_EXPIRE_PASSWORD')
    if uac & 0x20000 > 0:
        flags.append('MNS_LOGON_ACCOUNT')
    if uac & 0x40000 > 0:
        flags.append('SMARTCARD_REQUIRED')
    if uac & 0x80000 > 0:
        flags.append('TRUSTED_FOR_DELEGATION')
    if uac & 0x100000 > 0:
        flags.append('NOT_DELEGATED')
    if uac & 0x200000 > 0:
        flags.append('USE_DES_KEY_ONLY')
    if uac & 0x400000 > 0:
        flags.append('DONT_REQ_PREAUTH')
    if uac & 0x800000 > 0:
        flags.append('PASSWORD_EXPIRED')
    if uac & 0x1000000 > 0:
        flags.append('TRUSTED_TO_AUTH_FOR_DELEGATION')
    if uac & 0x04000000 > 0:
        flags.append('PARTIAL_SECRETS_ACCOUNT')
    return flags


def list_uac_colored_flags(uac):
    """Return a list of property flags as described at:
    https://support.microsoft.com/en-gb/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro"""
    flags = []
    if uac & 0x1 > 0:
        flags.append('SCRIPT')
    if uac & 0x2 > 0:
        flags.append(c_cyan('ACCOUNTDISABLE'))
    if uac & 0x8 > 0:
        flags.append('HOMEDIR_REQUIRED')
    if uac & 0x10 > 0:
        flags.append(c_orange('LOCKOUT'))
    if uac & 0x20 > 0:
        flags.append(c_white_on_red('PASSWD_NOTREQD'))
    if uac & 0x40 > 0:
        flags.append(c_red('PASSWD_CANT_CHANGE'))
    if uac & 0x80 > 0:
        flags.append(c_white_on_red('ENCRYPTED_TEXT_PWD_ALLOWED'))
    if uac & 0x100 > 0:
        flags.append('TEMP_DUPLICATE_ACCOUNT')
    if uac & 0x200 > 0:
        flags.append('NORMAL_ACCOUNT')
    if uac & 0x800 > 0:
        flags.append(c_cyan('INTERDOMAIN_TRUST_ACCOUNT'))
    if uac & 0x1000 > 0:
        flags.append(c_cyan('WORKSTATION_TRUST_ACCOUNT'))
    if uac & 0x2000 > 0:
        flags.append(c_cyan('SERVER_TRUST_ACCOUNT'))
    if uac & 0x10000 > 0:
        flags.append(c_red('DONT_EXPIRE_PASSWORD'))
    if uac & 0x20000 > 0:
        flags.append('MNS_LOGON_ACCOUNT')
    if uac & 0x40000 > 0:
        flags.append('SMARTCARD_REQUIRED')
    if uac & 0x80000 > 0:
        flags.append(c_orange('TRUSTED_FOR_DELEGATION'))
    if uac & 0x100000 > 0:
        flags.append('NOT_DELEGATED')
    if uac & 0x200000 > 0:
        flags.append(c_red('USE_DES_KEY_ONLY'))
    if uac & 0x400000 > 0:
        flags.append(c_red('DONT_REQ_PREAUTH'))
    if uac & 0x800000 > 0:
        flags.append(c_cyan('PASSWORD_EXPIRED'))
    if uac & 0x1000000 > 0:
        flags.append(c_orange('TRUSTED_TO_AUTH_FOR_DELEGATION'))
    if uac & 0x04000000 > 0:
        flags.append('PARTIAL_SECRETS_ACCOUNT')
    return flags


def str_samaccounttype(sat):
    """Return the SAM-Account-Type as described at:
    https://docs.microsoft.com/en-us/windows/desktop/adschema/a-samaccounttype"""
    if sat == 0x0:
        return 'SAM_DOMAIN_OBJECT'
    elif sat == 0x10000000:
        return 'SAM_GROUP_OBJECT'
    elif sat == 0x10000001:
        return 'SAM_NON_SECURITY_GROUP_OBJECT'
    elif sat == 0x20000000:
        return 'SAM_ALIAS_OBJECT'
    elif sat == 0x20000001:
        return 'SAM_NON_SECURITY_ALIAS_OBJECT'
    elif sat == 0x30000000:
        return 'SAM_USER_OBJECT'
    elif sat == 0x30000000:
        return 'SAM_NORMAL_USER_ACCOUNT'
    elif sat == 0x30000001:
        return 'SAM_MACHINE_ACCOUNT'
    elif sat == 0x30000002:
        return 'SAM_TRUST_ACCOUNT'
    elif sat == 0x40000000:
        return 'SAM_APP_BASIC_GROUP'
    elif sat == 0x40000001:
        return 'SAM_APP_QUERY_GROUP'
    elif sat == 0x7fffffff:
        return 'SAM_ACCOUNT_TYPE_MAX'
    else:
        return c_purple('Error: unknown value')


def str_object_type(entry):
    if 'sAMAccountType' in entry.entry_attributes_as_dict.keys():
        sat = entry.sAMAccountType.value
        if sat == 0x0:
            return 'domain'
        elif sat == 0x10000000:
            return 'group'
        elif sat == 0x30000000:
            return 'user'
        elif sat == 0x30000001:
            return 'computer'
        else:
            return c_purple('sAMAccountType = {}. Please complete this script.'.format(sat))
    else:
        return c_purple('Unable to find correct type (sAMAccountType not present).')


def list_trustType(trustType):
    """Return the trust type as defined here: https://msdn.microsoft.com/en-us/library/cc223771.aspx"""
    if trustType == 1:
        return 'The trusted domain is a Windows domain not running Active Directory.'
    elif trustType == 2:
        return 'The trusted domain is a Windows domain running Active Directory.'
    elif trustType == 3:
        return 'The trusted domain is running a non-Windows, RFC4120-compliant Kerberos distribution.'
    elif trustType == 4:
        return 'Historical reference; this value is not used in Windows.'
    else:
        return 'Error: unknown value.'


def list_trustDirection(trustDirection):
    """Return the trust direction as defined here: https://msdn.microsoft.com/en-us/library/cc223768.aspx"""
    if trustDirection == 0:
        return 'Disabled'
    elif trustDirection == 1:
        return c_green('Outbound')
    elif trustDirection == 2:
        return c_green('Inbound')
    elif trustDirection == 3:
        return c_cyan('Bidirectional')
    else:
        return c_purple('Error: unknown value.')


def list_trustAttributes(ta):
    """Return the trust attribute flags as defined here: https://msdn.microsoft.com/en-us/library/cc223779.aspx"""
    flags = []
    if ta & 0x1 > 0:
        flags.append('TRUST_ATTRIBUTE_NON_TRANSITIVE')
    if ta & 0x2 > 0:
        flags.append('TRUST_ATTRIBUTE_UPLEVEL_ONLY')
    if ta & 0x4 > 0:
        flags.append('TRUST_ATTRIBUTE_QUARANTINED_DOMAIN')
    if ta & 0x8 > 0:
        flags.append('TRUST_ATTRIBUTE_FOREST_TRANSITIVE')
    if ta & 0x10 > 0:
        flags.append('TRUST_ATTRIBUTE_CROSS_ORGANIZATION')
    if ta & 0x20 > 0:
        flags.append('TRUST_ATTRIBUTE_WITHIN_FOREST')
    if ta & 0x40 > 0:
        flags.append('TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL')
    if ta & 0x80 > 0:
        flags.append('TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION')
    if ta & 0x200 > 0:
        flags.append('TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION')
    if ta & 0x400 > 0:
        flags.append('TRUST_ATTRIBUTE_PIM_TRUST')
    return flags


def debug_var(var):
    print('\n===================')
    print('===   Debug var  ===')
    print('====================')
    print('type of var = {}'.format(type(var)))
    print('====================')
    if isinstance(var, dict):
        print('var is a dict:')
        for k in var:
            print('* {} = {}'.format(k, var[k]))
        print('====================')
    if isinstance(var, list):
        print('var is a list:')
        for i in var:
            print('* {}'.format(i))
        print('====================')
    if isinstance(var, str):
        print('var is a str:')
        print(var)
        print('====================')
    for i in sorted(var.__dir__()):
        print(i)
    print('====================')


def convert_sid_to_string(hexstr):
    value = codecs.encode(bytes(hexstr[0]), 'hex')
    init_value = bytes(hexstr[0])
    value = 'S-1-5'
    for i in range(8, len(init_value), 4):
        value += '-{}'.format(str(struct.unpack('<I', init_value[i:i+4])[0]))
    return value


class LdapsearchAd:

    hostname = None
    domain = None
    username = None
    password = None
    server = None
    connection = None

    last_errors = []

    def __init__(self, hostname, ssl=False, domain=None, username=None, password=None, hashes=None):
        self.hostname = hostname
        self.domain = domain
        self.username = username
        self.password = password
        self.hashes = hashes
        if self.hashes is not None:
            self.lmhash, self.nthash = self.hashes.split(':')

        try:
            self.server = ldap3.Server(self.hostname, use_ssl=ssl, get_info='ALL')
            if self.domain and self.username and self.password:
                self.connection = ldap3.Connection(self.server, user='{}\\{}'.format(self.domain, self.username), password=self.password, authentication='NTLM', auto_bind=True)
            elif self.hashes is not None:
                if self.lmhash == "":
                    self.lmhash = "aad3b435b51404eeaad3b435b51404ee"
                self.connection = ldap3.Connection(self.server, user='{}\\{}'.format(self.domain, self.username),
                                                   password=self.lmhash + ":" + self.nthash, authentication=ldap3.NTLM, auto_bind=True)
            else:
                self.connection = ldap3.Connection(self.server, auto_bind=True)
        except ldap3.core.exceptions.LDAPSocketOpenError:
            self.last_errors.append('Unable to connect to {}.'.format(self.hostname))
        except ldap3.core.exceptions.LDAPBindError as ldapbe:
            self.last_errors.append('Bind Error: {}'.format(ldapbe))

    def print_info(self):
        log_info('Forest functionality level = {}'.format(str_functionality_level(self.server.info.other['forestFunctionality'][0])))
        log_info('Domain functionality level = {}'.format(str_functionality_level(self.server.info.other['domainFunctionality'][0])))
        log_info('Domain controller functionality level = {}'.format(str_functionality_level(self.server.info.other['domainControllerFunctionality'][0])))
        log_info('rootDomainNamingContext = {}'.format(self.server.info.other['rootDomainNamingContext'][0]))
        log_info('defaultNamingContext = {}'.format(self.server.info.other['defaultNamingContext'][0]))
        log_info('ldapServiceName = {}'.format(self.server.info.other['ldapServiceName'][0]))
        log_info('naming_contexts = {}'.format(self.server.info.naming_contexts))

    def whoami(self):
        if self.server and self.connection:
            log_info(self.connection.extend.standard.who_am_i())
        else:
            log_error('Not connected to LDAP server. Please authenticate yourself before trying to search something.')

    def search(self, search_filter, attributes='*', size_limit=100):
        r = []
        if self.server and self.connection:
            base_dn = self.server.info.other.get('defaultNamingContext')[0]
            if search_filter[0] != '(':
                search_filter = '({})'.format(search_filter)
            try:
                self.connection.search(base_dn, search_filter, attributes=attributes, size_limit=size_limit)
                entries = self.connection.entries
                for entry in entries:
                    r.append(entry)
            except ldap3.core.exceptions.LDAPInvalidFilterError as e:
                log_error('{} (perhaps missing parenthesis?)'.format(e))
        else:
            log_error('Not connected to LDAP server. Please authenticate yourself before trying to search something.')
            sys.exit(4)
        return r

    def __list_groups(self, entry):
        """Return a list containing the CN of each group the parameter is member of."""
        if 'memberOf' not in entry.entry_attributes_as_dict.keys():
            return ['memberOf attribute not found']
        groups = []
        # dirty patch because "memberOf.value" return a string if there is only one group
        # and a list of string if there is more than one group
        logging.debug('type of memberOf = {}'.format(type(entry.memberOf.value)))
        if isinstance(entry.memberOf.value, str):
            groups_raw = [entry.memberOf.value]
        else:
            groups_raw = entry.memberOf.value
        for group in groups_raw:
            group_cn = re.search('CN=([^,]*),', group).group(1)
            if re.search('^(enterprise admins)$', group_cn, re.IGNORECASE):
                groups.append(c_red(group_cn))
            elif re.search('^(domain admins|admins du domaine)$', group_cn, re.IGNORECASE):
                groups.append(c_red(group_cn))
            elif re.search('^(administrators|administrateurs)$', group_cn, re.IGNORECASE):
                groups.append(c_red(group_cn))
            elif re.search('admin', group_cn, re.IGNORECASE):
                groups.append(c_orange(group_cn))
            else:
                groups.append(group_cn)
        return groups

    def __print_user_details(self, user, tab=''):
        """Print info of a user (samacountname and userAccountControl)."""
        log_info('{}{}'.format(tab, user.samAccountName.value))
        log_info('{}|___type: {}'.format(tab, str_object_type(user)))
        if 'displayName' in user.entry_attributes_as_dict.keys():
            log_info('{}|___displayName = {}'.format(tab, user.displayName.value))
        if 'description' in user.entry_attributes_as_dict.keys():
            log_info('{}|___description = {}'.format(tab, user.description.value))
        if 'adminCount' in user.entry_attributes_as_dict.keys():
            if user.admincount.value == 1:
                log_success('{}|___{}'.format(tab, c_red('The adminCount is set to 1')))
            elif user.admincount.value == 0:
                log_info('{}|___{}'.format(tab, 'adminCount = 0'))
            else:
                log_error('{}|___{}'.format(tab, 'Unknown value for adminCount: {}'.format(user.admincount.value)))
        if 'userAccountControl' in user.entry_attributes_as_dict.keys():
            log_info('{}|___userAccountControl = {}'.format(tab, ', '.join(list_uac_colored_flags(user.userAccountControl.value))))
        log_info('{}|___sAMAccountType = {}'.format(tab, str_samaccounttype(user.samaccounttype.value)))
        if 'memberOf' in user.entry_attributes_as_dict.keys():
            log_info('{}|___memberOf = {}'.format(tab, ', '.join(self.__list_groups(user))))

    def __print_user_brief(self, user, tab=''):
        """Print info of a user on a single line (samacountname and userAccountControl)."""
        if str_object_type(user) != 'user':
            if 'foreignSecurityPrincipal' in user.objectclass.value:
                log_info('{}{} (objectclass = foreignSecurityPrincipal, probably a user from another domain. Please investigate)'.format(tab, user.name.value))
            else:
                log_error('{}Invalid type for "{}", not a user?'.format(tab, user.name.value))
        else:
            uac_flags = list_uac_colored_flags(user.userAccountControl.value)
            uac_flags.remove('NORMAL_ACCOUNT')
            if uac_flags:
                log_success('{}{} ({})'.format(tab, user.sAMAccountName.value, ', '.join(uac_flags)))
            else:
                log_info('{}{}'.format(tab, user.sAMAccountName.value))

    def print_users(self, search_filter, attributes='*', size_limit=100):
        """Method to pretty print a set a users attributes."""
        r_search = self.search(search_filter, attributes, size_limit=size_limit)
        for user in r_search:
            self.__print_user_details(user)

    def print_users_list(self, search_filter, attributes='*', size_limit=100):
        """Method to pretty list print a set a users attributes."""
        r_search = self.search(search_filter, attributes, size_limit=size_limit)
        for user in r_search:
            self.__print_user_brief(user)

    def print_admins(self, size_limit=100):
        """Method to get a list of members of the "admin" group."""
        search_filter = '|(CN=Administrators)(CN=Administrateurs)(CN=Admins du domaine)(CN=Domain Admins)(CN=Enterprise Admins)'
        # Get the exact distinguishedName of the "admin" group
        # needed to perform a recursive search of members of members of members ...
        r_search = self.search(search_filter, ['distinguishedName', 'cn'], size_limit=10)
        for admin_group in r_search:
            admins_dn = admin_group.distinguishedName.value
            print('All members of group "{}":'.format(admin_group.cn.value))
            # from this distinguishedName, find all members recursively
            search_filter = '(&(memberOf:1.2.840.113556.1.4.1941:={})(!(objectClass=group)))'.format(admins_dn)
            attributes = ['objectClass', 'name', 'userAccountControl', 'sAMAccountName', 'sAMAccountType']
            r_search = self.search(search_filter, attributes, size_limit=size_limit)
            for result in r_search:
                self.__print_user_brief(result, '    ')

    def print_trusts(self):
        """Method to get infos about trusts."""
        for trust in self.search('objectClass=trustedDomain'):
            log_info('+ {} ({})'.format(trust.name.value, trust.flatName.value))
            log_info('|___trustAttributes = {}'.format(list_trustAttributes(trust.trustAttributes.value)))
            log_info('|___trustDirection = {}'.format(list_trustDirection(trust.trustDirection.value)))
            log_info('|___trustType = {}'.format(list_trustType(trust.trustType.value)))
            log_info('|___trustPartner = {}'.format(trust.trustPartner.value))
            if 'securityIdentifier' in trust:
                log_info('|___securityIdentifier = {}'.format(ldap3.protocol.formatters.formatters.format_sid(trust.securityIdentifier.value)))
            log_info('|___whenCreated = {}'.format(trust.whenCreated.value))
            log_info('|___whenChanged = {}'.format(trust.whenChanged.value))

    def print_kerberoast(self):
        """Method to get infos about kerberoastable users."""
        search_filter = '(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
        search_attributes = ['cn', 'samaccountname', 'serviceprincipalname']
        for kerberoastable_user in self.search(search_filter, search_attributes):
            log_success('{}'.format(kerberoastable_user))

    def print_search_spn(self, search_filter, size_limit=100):
        """Method to find services registered in the AD."""
        if not re.search('serviceprincipalname', search_filter, re.IGNORECASE):
            search_filter = '(servicePrincipalName={}*)'.format(search_filter)
        search_attributes = ['cn', 'samaccountname', 'serviceprincipalname']
        for spn_user in self.search(search_filter, search_attributes, size_limit=size_limit):
            log_success('{}'.format(spn_user))

    def print_asreqroast(self):
        """Method to get all accounts that are vulnerable to ASREPRoast.
        Filter based on https://www.tarlogic.com/en/blog/how-to-attack-kerberos/"""
        search_filter = '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
        search_attributes = ['cn', 'samaccountname']
        for asreqroastuser in self.search(search_filter, search_attributes):
            log_success('{}'.format(asreqroastuser))

    def print_lastpwchangekrbtgt(self):
        """Method to retreive the last time the password for krbtgt was reset."""
        search_filter = '(cn=krbtgt)'
        search_attributes = ['whenChanged']
        log_info(self.search(search_filter, search_attributes))

    def print_search_delegation(self):
        """Method to retreive accounts with delegation set"""
        search_filter = '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
        search_attributes = ['cn', 'samaccountname']
        for accountdelegation in self.search(search_filter, search_attributes):
            log_success('{}'.format(accountdelegation))

    def __print_default_pass_pol(self, pass_pol):
        """Print info about the default password policy."""
        print('Default password policy:')
        attributes = pass_pol.entry_attributes_as_dict
        pass_len = attributes['minPwdLength'][0]
        # Password length
        if pass_len < 8:
            log_info('|___Minimum password length = {}'.format(c_red(pass_len)))
        elif pass_len < 12:
            log_info('|___Minimum password length = {}'.format(c_orange(pass_len)))
        else:
            log_info('|___Minimum password length = {}'.format(c_green(pass_len)))
        # Password properties as described here: https://ldapwiki.com/wiki/PwdProperties
        pass_properties = attributes['pwdProperties'][0]
        if pass_properties & 1 > 0:
            log_info('|___Password complexity = {}'.format(c_green('Enabled')))
        else:
            log_info('|___Password complexity = {}'.format(c_red('Disabled')))
        # Lockout settings
        if attributes['lockoutThreshold'][0] == 0:
            log_success('|___Lockout threshold = {}'.format(c_white_on_red('Disabled')))
        else:
            log_info('|___Lockout threshold = {}'.format(attributes['lockoutThreshold'][0]))
            log_info('|___  Lockout duration = {}'.format(str_human_date(attributes['lockoutDuration'][0])))
            log_info('|___  Lockout observation window = {}'.format(str_human_date(attributes['lockOutObservationWindow'][0])))

    def __print_pass_pol(self, pass_pol):
        """Print info about a Fine-Grained Password Policy."""
        print('Fined grained password policy found: {}'.format(c_cyan(pass_pol.cn.value)))
        attributes = pass_pol.entry_attributes_as_dict
        log_info('|____Password settings precedence = {}'.format(attributes['msDS-PasswordSettingsPrecedence'][0]))
        pass_len = attributes['msDS-MinimumPasswordLength'][0]
        # Password length
        if pass_len < 8:
            log_info('|___Minimum password length = {}'.format(c_red(pass_len)))
        elif pass_len < 12:
            log_info('|___Minimum password length = {}'.format(c_orange(pass_len)))
        else:
            log_info('|___Minimum password length = {}'.format(c_green(pass_len)))
        # Password complexity
        if attributes['msDS-PasswordComplexityEnabled'][0]:
            log_info('|___Password complexity enabled = {}'.format(c_green(attributes['msDS-PasswordComplexityEnabled'][0])))
        else:
            log_info('|___Password complexity enabled = {}'.format(c_red(attributes['msDS-PasswordComplexityEnabled'][0])))
        # Password reversible encryption?
        if attributes['msDS-PasswordReversibleEncryptionEnabled'][0]:
            log_info('|___Password reversible encryption enabled = {}'.format(c_white_on_red(attributes['msDS-PasswordReversibleEncryptionEnabled'][0])))
        else:
            log_info('|___Password reversible encryption enabled = {}'.format(attributes['msDS-PasswordReversibleEncryptionEnabled'][0]))
        # Lockout settings
        if attributes['msDS-LockoutThreshold'][0] == 0:
            log_success('|___Lockout threshold = {}'.format(c_white_on_red('Disabled')))
        else:
            log_info('|___Lockout threshold = {}'.format(attributes['msDS-LockoutThreshold'][0]))
            log_info('|___  Lockout duration = {}'.format(str_human_date(attributes['msDS-LockoutDuration'][0])))
            log_info('|___  Lockout observation window = {}'.format(str_human_date(attributes['msDS-LockoutObservationWindow'][0])))

    def print_pass_pols(self):
        """Main function to get info about password policies."""
        # get default password policy
        default_pps = self.search('(objectClass=domainDNS)', size_limit=5)
        if len(default_pps) > 1:
            log_error('More than one "default password policy" found. Should not happened. Please investigate and correct the script.')
            sys.exit(6)
        self.__print_default_pass_pol(default_pps[0])
        # get Fine Grained Password Policies
        fgpps = self.search('(objectClass=MsDS-PasswordSettings)', size_limit=100)
        if len(fgpps) <= 0:
            log_info('No fine grained password policy found (high privileges are required).')
        for fgpp in fgpps:
            self.__print_pass_pol(fgpp)

    def print_creator_sid(self):
        """Main function to get info about createsid from ms-ds-creatorsid."""
        # get all createsid without parse
        search_filter = '(&(ms-ds-creatorsid=*))'
        search_attributes = ['sAMAccountName', 'mS-DS-CreatorSID']
        for asreqroastuser in self.search(search_filter, search_attributes):
            log_success('{}'.format(asreqroastuser))
            if asreqroastuser['mS-DS-CreatorSID'] != "":
                sid_str = convert_sid_to_string(asreqroastuser['mS-DS-CreatorSID'])

            log_info(sid_str)
            # parse objectSid
            search_filter_get_name = '(objectSid={})'.format(sid_str)
            search_attributes_get_name = ['sAMAccountName']
            asreqroastuser_get_name_obj = self.search(search_filter_get_name, search_attributes_get_name)
            if asreqroastuser_get_name_obj:
                for asreqroastuser_get_name in asreqroastuser_get_name_obj:
                    if asreqroastuser_get_name['sAMAccountName'] is not None:
                        log_info('CreatorSID: {}'.format(asreqroastuser_get_name['sAMAccountName']))
            else:
                log_error("Maybe already deleted")
            print("")


def main():
    # Parse arguments
    argParser = argparse.ArgumentParser(description="Active Directory LDAP Enumerator")
    argParser.add_argument('-l', '--server', required=True, dest='ldap_server', help='IP address of the LDAP server.')
    argParser.add_argument('-ssl', '--ssl', dest='ssl', action='store_true', help='Force an SSL connection?.')
    argParser.add_argument('-t', '--type', required=True, dest='request_type', help='Request type: info, whoami, search, search-large, trusts,\
        pass-pols, show-admins, show-user, show-user-list, kerberoast, createsid, all')
    argParser.add_argument('-d', '--domain', dest='domain', help='Authentication account\'s FQDN. Example: "contoso.local".')
    argParser.add_argument('-u', '--username', dest='username', help='Authentication account\'s username.')
    argParser.add_argument('-p', '--password', dest='password', help='Authentication account\'s password.')
    argParser.add_argument('-H', '-hashes', dest="hashes", help='NTLM hashes, format is LMHASH:NTHASH')
    argParser.add_argument('-s', '--search-filter', dest='search_filter', help='Search filter (use LDAP format).')
    argParser.add_argument('search_attributes', default='*', nargs='*', help='LDAP attributes to look for (default is all).')
    argParser.add_argument('-z', '--size_limit', dest='size_limit', default=100, help='Size limit (default is 100, or server\' own limit).')
    argParser.add_argument('-o', '--output', dest='output_file', help='Write results in specified file too.')
    argParser.add_argument('-v', '--verbose', dest='verbosity', help='Turn on debug mode', action='store_true')
    args = argParser.parse_args()

    # Set mandatory arguments for each request_type
    mandatory_arguments = {}
    mandatory_arguments['info'] = []
    mandatory_arguments['whoami'] = ['domain', 'username']
    mandatory_arguments['search'] = ['domain', 'username', 'search_filter']
    mandatory_arguments['search-large'] = ['domain', 'username', 'search_filter']
    mandatory_arguments['trusts'] = ['domain', 'username']
    mandatory_arguments['pass-pols'] = ['domain', 'username']
    mandatory_arguments['admins'] = ['domain', 'username']
    mandatory_arguments['show-user'] = ['domain', 'username', 'search_filter']
    mandatory_arguments['show-user-list'] = ['domain', 'username', 'search_filter']
    mandatory_arguments['kerberoast'] = ['domain', 'username']
    mandatory_arguments['search-spn'] = ['domain', 'username', 'search_filter']
    mandatory_arguments['asreproast'] = ['domain', 'username']
    mandatory_arguments['goldenticket'] = ['domain', 'username']
    mandatory_arguments['search-delegation'] = ['domain', 'username']
    mandatory_arguments['createsid'] = ['domain', 'username']
    mandatory_arguments['all'] = ['domain', 'username']
    actions = [i.strip() for i in args.request_type.split(',')]
    for action in actions:
        if action not in mandatory_arguments.keys():
            argParser.error('request type must be one of: {}.'.format(', '.join(mandatory_arguments.keys())))
        for mandatory_argument in mandatory_arguments[action]:
            if vars(args)[mandatory_argument] is None:
                argParser.error('{} argument is mandatory with request type = {}'.format(mandatory_argument, action))

    # Configure logging to stdout
    logger = logging.getLogger()
    handler = logging.StreamHandler(sys.stdout)
    if args.verbosity:
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter(fmt='%(asctime)-19s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d_%H:%M:%S')
    else:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter(fmt='%(message)s')
    handler.setFormatter(formatter)
    if args.output_file:
        f_handler = logging.FileHandler(args.output_file)
        f_handler.setFormatter(formatter)
        logger.addHandler(f_handler)
    logger.addHandler(handler)

    # Connection to the LDAP server using credentials provided in argument
    ldap = LdapsearchAd(args.ldap_server, args.ssl, args.domain, args.username, args.password, args.hashes)
    if not ldap.server or not ldap.connection:
        log_error('Error, unable to connect to {} using {}\\{}'.format(args.ldap_server, args.domain, args.username))
        for error in ldap.last_errors:
            log_error(error)
        sys.exit(3)

    for action in actions:

        # Get the server's infos
        if action == 'info':
            log_title('Server infos', 3)
            ldap.print_info()

        # Check the connection and retrieve the username used for the connection
        elif action == 'whoami':
            log_title('Result of "whoami" command', 3)
            ldap.whoami()

        # Raw search
        elif action == 'search':
            log_title('Result of "search" command', 3)
            result = ldap.search(args.search_filter, args.search_attributes, args.size_limit)
            for entry in result:
                log_info('DN = {}'.format(entry.entry_dn))
                for attribute in sorted(entry.entry_attributes):
                    log_info('|___{} = {}'.format(attribute, entry[attribute]))

        # Get users
        elif action == 'show-user':
            log_title('Result of "show-user" command', 3)
            ldap.print_users(args.search_filter, args.search_attributes, args.size_limit)

        # Get users
        elif action == 'show-user-list':
            log_title('Result of "show-user" command', 3)
            ldap.print_users_list(args.search_filter, args.search_attributes, args.size_limit)

        # Get admins
        elif action == 'admins':
            log_title('Result of "admins" command', 3)
            ldap.print_admins()

        # Get kerberoastable users accounts
        elif action == 'pass-pols':
            log_title('Result of "pass-pols" command', 3)
            ldap.print_pass_pols()

        # Get trusts
        elif action == 'trusts':
            log_title('Result of "trusts" command', 3)
            ldap.print_trusts()

        # Get kerberoastable users accounts
        elif action == 'kerberoast':
            log_title('Result of "kerberoast" command', 3)
            ldap.print_kerberoast()

        # Get ASRepRoast user account
        elif action == 'asreproast':
            log_title('Result of "asreproast" command', 3)
            ldap.print_asreqroast()

        elif action == 'search-spn':
            log_title('Result of "search-spn" command', 3)
            ldap.print_search_spn(args.search_filter, args.size_limit)

        elif action == 'goldenticket':
            log_title('Result of "goldenticket" command', 3)
            ldap.print_lastpwchangekrbtgt()

        elif action == 'search-delegation':
            log_title('Result of "search-delegation" command', 3)
            ldap.print_search_delegation()

        elif action == 'createsid':
            log_title('Result of "createsid" command', 3)
            ldap.print_creator_sid()

        # Run all checks
        elif action == 'all':
            log_title('Server infos', 3)
            ldap.print_info()
            log_title('Result of "admins" command', 3)
            ldap.print_admins()
            log_title('Result of "pass-pols" command', 3)
            ldap.print_pass_pols()
            log_title('Result of "trusts" command', 3)
            ldap.print_trusts()
            log_title('Result of "kerberoast" command', 3)
            ldap.print_kerberoast()
            log_title('Result of "asreqroast" command', 3)
            ldap.print_asreqroast()
            log_title('Result of "goldenticket" command', 3)
            ldap.print_lastpwchangekrbtgt()
            log_title('Result of "search-delegation" command', 3)
            ldap.print_search_delegation()
            log_title('Result of "creatorsid" command', 3)
            ldap.print_creator_sid()
        else:
            log_error('Error: This functionnality is not implemented yet. Please implement it now.')


if __name__ == '__main__':
    main()
