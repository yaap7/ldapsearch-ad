import ldap3
import logging
import re

from .colors import c_green
from .colors import c_orange
from .colors import c_red
from .colors import c_white_on_red
from .colors import c_cyan

from .exceptions import LsaException

from .logging import log_error
from .logging import log_warning
from .logging import log_info
from .logging import log_success

from .utils import str_human_date
from .utils import str_functionality_level
from .utils import list_uac_colored_flags
from .utils import str_samaccounttype
from .utils import str_object_type
from .utils import list_trust_type
from .utils import list_trust_direction
from .utils import list_trust_attributes
from .utils import convert_sid_to_string


class LdapsearchAd:

    hostname = None
    port = None
    domain = None
    username = None
    password = None
    server = None
    connection = None

    last_errors: list = []

    def __init__(
        self,
        hostname,
        # default ldaps port if not specified
        port=636,
        ssl=False,
        domain=None,
        username=None,
        password=None,
        hashes=None,
    ):
        self.hostname = hostname
        self.port = port
        self.domain = domain
        self.username = username
        self.password = password
        self.hashes = hashes
        if self.hashes is not None:
            try:
                self.lmhash, self.nthash = self.hashes.split(":")
            except ValueError as ve:
                print("Error: The hash need to be in the following format:")
                print(
                    "aad3b435b51404eeaad3b435b51404ee:382c7bf814461d8d685cf7a7a06c8c8f"
                )
                print("")
                raise ve
        try:
            self.server = ldap3.Server(
                self.hostname, self.port, use_ssl=ssl, get_info="ALL"
            )
            if self.domain and self.username:
                if self.password:
                    self.connection = ldap3.Connection(
                        self.server,
                        user=f"{self.domain}\\{self.username}",
                        password=self.password,
                        authentication="NTLM",
                        auto_bind=True,
                        read_only=True,
                    )
                elif self.hashes is not None:
                    if self.lmhash == "":
                        self.lmhash = "aad3b435b51404eeaad3b435b51404ee"
                    self.connection = ldap3.Connection(
                        self.server,
                        user=f"{self.domain}\\{self.username}",
                        password=self.lmhash + ":" + self.nthash,
                        authentication=ldap3.NTLM,
                        auto_bind=True,
                        read_only=True,
                    )
                else:
                    raise LsaException(
                        "Need either password or hash to try to authenticate."
                    )
            else:
                self.connection = ldap3.Connection(
                    self.server, auto_bind=True, read_only=True
                )
        except ldap3.core.exceptions.LDAPSocketOpenError as ldapsoe:
            self.last_errors.append(f"Unable to connect to {self.hostname}.")
            raise ldapsoe
        except ldap3.core.exceptions.LDAPBindError as ldapbe:
            self.last_errors.append(f"Bind Error: {ldapbe}")
            raise ldapbe

    def is_connected(self):
        return self.server is not None and self.connection is not None

    def is_authenticated(self):
        return (
            self.server is not None
            and self.connection is not None
            and self.connection.authentication != ldap3.ANONYMOUS
        )

    def infos(self):
        if not self.is_connected():
            raise LsaException("Need to be connected before reading server's infos.")
        log_info(
            f'Forest functionality level = {str_functionality_level(self.server.info.other["forestFunctionality"][0])}'
        )
        log_info(
            f'Domain functionality level = {str_functionality_level(self.server.info.other["domainFunctionality"][0])}'
        )
        log_info(
            f'Domain controller functionality level = {str_functionality_level(self.server.info.other["domainControllerFunctionality"][0])}'
        )
        log_info(
            f'rootDomainNamingContext = {self.server.info.other["rootDomainNamingContext"][0]}'
        )
        log_info(
            f'defaultNamingContext = {self.server.info.other["defaultNamingContext"][0]}'
        )
        log_info(f'ldapServiceName = {self.server.info.other["ldapServiceName"][0]}')
        log_info(f"naming_contexts = {self.server.info.naming_contexts}")

    def whoami(self):
        if not self.is_connected():
            raise LsaException(
                "Need to be connected before trying to check who you are."
            )
        if self.connection.extend.standard.who_am_i():
            log_success(self.connection.extend.standard.who_am_i())
        else:
            log_error("<not_connected>")

    def search(self, search_filter, attributes="*", size_limit=100, page_size=1000):
        """Warning: returns a generator!
        Thus, it is not backward compatible with the old_search
        Arguments:
        * search_filter = '(samaccountname=adm*)'
        * attributes = ['cn', 'givenName'] or '*' for all attributes
        Return value:
        * a generator of CaseInsensitiveDict"""

        if not self.is_authenticated():
            raise LsaException(
                "Need to be authenticated before trying to search for something."
            )
        if isinstance(size_limit, str):
            try:
                size_limit = int(size_limit)
            except ValueError:
                raise LsaException("size_limit (-z) should be a valid integer")
        nb_entries = 0
        base_dn = self.server.info.other.get("defaultNamingContext")[0]
        self.connection.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=attributes,
            paged_size=page_size,
            size_limit=size_limit,
        )
        for entry in self.connection.response:
            if entry["type"] == "searchResEntry":
                nb_entries += 1
                yield entry["attributes"]
        if "controls" in self.connection.result:
            cookie = self.connection.result["controls"]["1.2.840.113556.1.4.319"][
                "value"
            ]["cookie"]
            size_limit -= nb_entries
            nb_entries = 0
        else:
            size_limit = 0
            cookie = None
        while size_limit > 0 and cookie:
            self.connection.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=attributes,
                paged_size=page_size,
                size_limit=size_limit,
                paged_cookie=cookie,
            )
            for entry in self.connection.response:
                if entry["type"] == "searchResEntry":
                    nb_entries += 1
                    yield entry["attributes"]
            if "controls" in self.connection.result:
                cookie = self.connection.result["controls"]["1.2.840.113556.1.4.319"][
                    "value"
                ]["cookie"]
                size_limit -= nb_entries
                nb_entries = 0
            else:
                size_limit = 0
                cookie = None

    def __list_groups(self, entry):
        """Return a list containing the CN of each group the parameter is member of."""
        if "memberOf" not in entry:
            return ["memberOf attribute not found"]
        groups = []
        # dirty patch because "memberOf.value" return a string if there is only one group
        # and a list of string if there is more than one group
        logging.debug(f'type of memberOf = {type(entry["memberOf"])}')
        if isinstance(entry["memberOf"], str):
            groups_raw = [entry["memberOf"]]
        else:
            groups_raw = entry["memberOf"]
        for group in groups_raw:
            group_cn = re.search("CN=([^,]*),", group).group(1)
            if re.search("^(enterprise admins)$", group_cn, re.IGNORECASE):
                groups.append(c_red(group_cn))
            elif re.search(
                "^(domain admins|admins du domaine)$", group_cn, re.IGNORECASE
            ):
                groups.append(c_red(group_cn))
            elif re.search(
                "^(administrators|administrateurs)$", group_cn, re.IGNORECASE
            ):
                groups.append(c_red(group_cn))
            elif re.search("admin", group_cn, re.IGNORECASE):
                groups.append(c_orange(group_cn))
            else:
                groups.append(group_cn)
        return groups

    def __print_user_details(self, user, tab=""):
        """Print info of a user (samacountname and userAccountControl)."""
        log_info(f'{tab}{user["samAccountName"]}')
        log_info(f"{tab}|__ type: {str_object_type(user)}")
        if "displayName" in user:
            log_info(f'{tab}|__ displayName = {user["displayName"]}')
        if "description" in user:
            log_info(f'{tab}|__ description = {user["description"]}')
        if "adminCount" in user:
            if user["admincount"] == 1:
                log_success(f'{tab}|__ {c_red("The adminCount is set to 1")}')
            elif user["admincount"] == 0:
                log_info(f'{tab}|__ {"adminCount = 0"}')
            else:
                log_error(
                    f'{tab}|__ Unknown value for adminCount: {user["admincount"]}'
                )
        if "userAccountControl" in user:
            log_info(
                f'{tab}|__ userAccountControl = {", ".join(list_uac_colored_flags(user["userAccountControl"]))}'
            )
        log_info(
            f'{tab}|__ sAMAccountType = {str_samaccounttype(user["samaccounttype"])}'
        )
        if "memberOf" in user:
            log_info(f'{tab}|__ memberOf = {", ".join(self.__list_groups(user))}')

    def __print_user_brief(self, user, tab=""):
        """Print info of a user on a single line (samacountname and userAccountControl)."""
        if str_object_type(user) != "user":
            if "foreignSecurityPrincipal" in user["objectclass"]:
                log_info(
                    f'{tab}{user["sAMAccountName"]} (objectclass = foreignSecurityPrincipal, probably a user from another domain. Please investigate)'
                )
            else:
                log_warning(
                    f'{tab}{user["sAMAccountName"]} ({c_orange(str_object_type(user))})'
                )
        else:
            uac_flags = list_uac_colored_flags(user["userAccountControl"])
            uac_flags.remove("NORMAL_ACCOUNT")
            if uac_flags:
                log_success(f'{tab}{user["sAMAccountName"]} ({", ".join(uac_flags)})')
            else:
                log_info(f'{tab}{user["sAMAccountName"]}')

    def __print_group_brief(self, group, tab=""):
        """Print info of a group on a single line (samacountname and description)."""
        if isinstance(group["description"], list):
            description = " - ".join(group["description"])
        else:
            description = str(group["description"])
        if "member" in group:
            nb_members = len(group["member"])
        else:
            nb_members = 0
        log_info(
            f'{tab}{group["sAMAccountName"]}§{str_object_type(group)}§{description}§{nb_members}'
        )

    def print_users(self, search_filter, attributes="*", size_limit=100):
        """Method to pretty print a set a users attributes."""
        r_search = self.search(search_filter, attributes, size_limit=size_limit)
        for user in r_search:
            self.__print_user_details(user)

    def print_users_list(self, search_filter, attributes="*", size_limit=100):
        """Method to pretty list print a set a users attributes."""
        r_search = self.search(search_filter, attributes, size_limit=size_limit)
        for user in r_search:
            self.__print_user_brief(user)

    def print_member_of(self, group_cn, size_limit=100):
        """Print the list of users who a member of a specific group.
        Also use the nested groups"""
        search_filter = f"(CN={group_cn})"
        # Get the exact distinguishedName of the requested group
        # needed to perform a recursive search of members of members of members ...
        targeted_groups = self.search(
            search_filter, ["distinguishedName", "cn"], size_limit=100
        )
        # should be only one...
        for targeted_group in targeted_groups:
            group_dn = targeted_group["distinguishedName"]
            log_info(f'All members of group "{targeted_group["cn"]}":')
            # from this distinguishedName, find all members recursively
            search_filter = f"(&(memberOf:1.2.840.113556.1.4.1941:={group_dn})(!(objectClass=group)))"
            attributes = [
                "objectClass",
                "name",
                "userAccountControl",
                "sAMAccountName",
                "sAMAccountType",
            ]
            users = self.search(search_filter, attributes, size_limit=size_limit)
            for user in users:
                self.__print_user_brief(user, "    ")

    def print_search_foreign_security_principals(self, size_limit=100):
        """Print the list of foreign security principals who are members of
        domain local groups in the current forest"""
        search_filter = "(objectclass=foreignSecurityPrincipal)"
        attributes = ["name", "objectSid", "distinguishedName", "objectClass"]
        fsp = self.search(search_filter, attributes, size_limit=size_limit)
        for sp in fsp:
            log_info(f'name = {sp["name"]}')
            log_info(f'|__ objectSid = {sp["objectSid"]}')
            log_info(f'|__ distinguishedName = {sp["distinguishedName"]}')
            log_info(f'|__ objectClass = {sp["objectClass"]}')

    def print_user_of(self, search_filter, size_limit=100):
        """Print the list of groups whom a user is member of.
        Also use the nested groups"""
        # Get the exact distinguishedName of the requested user
        # needed to perform a recursive search of his groups ...
        targeted_users = self.search(
            search_filter, ["distinguishedName", "cn"], size_limit=100
        )
        # should be only one...
        for targeted_user in targeted_users:
            user_dn = targeted_user["distinguishedName"]
            log_info(f'All groups of user "{targeted_user["cn"]}":')
            # from this distinguishedName, find all members recursively
            search_filter = f"(member:1.2.840.113556.1.4.1941:={user_dn})"
            attributes = [
                "objectClass",
                "description",
                "cn",
                "member",
                "sAMAccountName",
                "sAMAccountType",
            ]
            groups = self.search(search_filter, attributes, size_limit=size_limit)
            for group in groups:
                self.__print_group_brief(group, "    ")

    def print_trusts(self):
        """Method to get infos about trusts."""
        for trust in self.search("(objectClass=trustedDomain)"):
            log_info(f'+ {trust["name"]} ({trust["flatName"]})')
            log_info(
                f'|__ trustAttributes = {list_trust_attributes(trust["trustAttributes"])}'
            )
            log_info(
                f'|__ trustDirection = {list_trust_direction(trust["trustDirection"])}'
            )
            log_info(f'|__ trustType = {list_trust_type(trust["trustType"])}')
            log_info(f'|__ trustPartner = {trust["trustPartner"]}')
            if "securityIdentifier" in trust:
                log_info(
                    f'|__ securityIdentifier = {ldap3.protocol.formatters.formatters.format_sid(trust["securityIdentifier"])}'
                )
            log_info(f'|__ whenCreated = {trust["whenCreated"]}')
            log_info(f'|__ whenChanged = {trust["whenChanged"]}')

    def __print_default_pass_pol(self, pass_pol):
        """Print info about the default password policy."""
        log_info("Default password policy:")
        min_pass_len = pass_pol["minPwdLength"]
        # Password length
        if min_pass_len < 8:
            log_info(f"|__ Minimum password length = {c_red(min_pass_len)}")
        elif min_pass_len < 12:
            log_info(f"|__ Minimum password length = {c_orange(min_pass_len)}")
        else:
            log_info(f"|__ Minimum password length = {c_green(min_pass_len)}")
        # Password properties as described here: https://ldapwiki.com/wiki/PwdProperties
        pass_properties = pass_pol["pwdProperties"]
        if pass_properties & 1 > 0:
            log_info(f'|__ Password complexity = {c_green("Enabled")}')
        else:
            log_info(f'|__ Password complexity = {c_red("Disabled")}')
        # Lockout settings
        if pass_pol["lockoutThreshold"] == 0:
            log_success(f'|__ Lockout threshold = {c_white_on_red("Disabled")}')
        else:
            if pass_pol["lockoutThreshold"] > 5:
                log_success(f'|__ Lockout threshold = {pass_pol["lockoutThreshold"]}')
            else:
                log_info(f'|__ Lockout threshold = {pass_pol["lockoutThreshold"]}')
            log_info(
                f'|__ Lockout duration = {str_human_date(pass_pol["lockoutDuration"])}'
            )
            log_info(
                f'|__ Lockout observation window = {str_human_date(pass_pol["lockOutObservationWindow"])}'
            )
        # Password history length
        if pass_pol["pwdHistoryLength"] > 0:
            log_success(f'|__ Password history length = {pass_pol["pwdHistoryLength"]}')
        else:
            log_info(f'|__ Password history length = {pass_pol["pwdHistoryLength"]}')
        # Password min and max age
        log_info(f'|__ Max password age = {str_human_date(pass_pol["maxPwdAge"])}')
        log_info(f'|__ Min password age = {str_human_date(pass_pol["minPwdAge"])}')

    def __print_pass_pol(self, pass_pol):
        """Print info about a Fine-Grained Password Policy."""
        log_info(f'Fined grained password policy found: {c_cyan(pass_pol["cn"])}')
        log_info(
            f'|__ Password settings precedence = {pass_pol["msDS-PasswordSettingsPrecedence"]}'
        )
        pass_len = pass_pol["msDS-MinimumPasswordLength"]
        # Password length
        if pass_len < 8:
            log_info(f"|__ Minimum password length = {c_red(pass_len)}")
        elif pass_len < 12:
            log_info(f"|__ Minimum password length = {c_orange(pass_len)}")
        else:
            log_info(f"|__ Minimum password length = {c_green(pass_len)}")
        # Password complexity
        if pass_pol["msDS-PasswordComplexityEnabled"]:
            log_info(f'|__ Password complexity enabled = {c_green("Enabled")}')
        else:
            log_info(f'|__ Password complexity enabled = {c_red("Disabled")}')
        # Password reversible encryption?
        if pass_pol["msDS-PasswordReversibleEncryptionEnabled"]:
            log_info(
                f'|__ Password reversible encryption enabled = {c_white_on_red(pass_pol["msDS-PasswordReversibleEncryptionEnabled"])}'
            )
        else:
            log_info(
                f'|__ Password reversible encryption enabled = {pass_pol["msDS-PasswordReversibleEncryptionEnabled"]}'
            )
        # Lockout settings
        if pass_pol["msDS-LockoutThreshold"] == 0:
            log_success(f'|__ Lockout threshold = {c_white_on_red("Disabled")}')
        else:
            log_info(f'|__ Lockout threshold = {pass_pol["msDS-LockoutThreshold"]}')
            log_info(
                f'|__ Lockout duration = {str_human_date(pass_pol["msDS-LockoutDuration"])}'
            )
            log_info(
                f'|__ Lockout observation window = {str_human_date(pass_pol["msDS-LockoutObservationWindow"])}'
            )
        # Password history length
        if pass_pol["msDS-PasswordHistoryLength"] > 0:
            log_success(
                f'|__ Password history length = {pass_pol["msDS-PasswordHistoryLength"]}'
            )
        else:
            log_info(
                f'|__ Password history length = {pass_pol["msDS-PasswordHistoryLength"]}'
            )
        # Password min and max age
        log_info(
            f'|__ Max password age = {str_human_date(pass_pol["msDS-MaximumPasswordAge"])}'
        )
        log_info(
            f'|__ Min password age = {str_human_date(pass_pol["msDS-MinimumPasswordAge"])}'
        )
        log_info(f'|__ PSO applies to = {pass_pol["msDS-PSOAppliesTo"]}')

    def print_pass_pols(self):
        """Main function to get info about password policies."""
        # get default password policy
        default_pps = self.search("(objectClass=domainDNS)", size_limit=5)
        nb_default_pps = 0
        for default_pp in default_pps:
            nb_default_pps += 1
            self.__print_default_pass_pol(default_pp)
        if nb_default_pps > 1:
            raise LsaException(
                'More than one "default password policy" found. Should not happened. Please investigate and correct the script.'
            )
        # get Fine Grained Password Policies
        fgpps = self.search("(objectClass=MsDS-PasswordSettings)", size_limit=100)
        nb_fgpps = 0
        for fgpp in fgpps:
            nb_fgpps += 1
            self.__print_pass_pol(fgpp)
        if nb_fgpps <= 0:
            log_info(
                "No fine grained password policy found (high privileges are required)."
            )

    def print_admins(self, size_limit=100):
        """Method to get a list of members of the "admin" group."""
        english_groups = "(CN=Administrators)(CN=Domain Admins)(CN=Enterprise Admins)"
        french_groups = "(CN=Administrateurs)(CN=Admins du domaine)(CN=Administrateurs de l’entreprise)"
        search_filter = f"(|{english_groups}{french_groups})"
        # Get the exact distinguishedName of the "admin" group
        # needed to perform a recursive search of members of members of members ...
        admin_groups = self.search(
            search_filter, ["distinguishedName", "cn"], size_limit=10
        )
        for admin_group in admin_groups:
            admins_dn = admin_group["distinguishedName"]
            log_info(f'All members of group "{admin_group["cn"]}":')
            # from this distinguishedName, find all members recursively
            search_filter = f"(&(memberOf:1.2.840.113556.1.4.1941:={admins_dn})(!(objectClass=group)))"
            attributes = [
                "objectClass",
                "name",
                "userAccountControl",
                "sAMAccountName",
                "sAMAccountType",
            ]
            admins = self.search(search_filter, attributes, size_limit=size_limit)
            for admin in admins:
                self.__print_user_brief(admin, "    ")

    def __print_user_with_spn(self, user):
        spns = ", ".join(user["servicePrincipalName"])
        log_success(f"{user['sAMAccountName']}: {spns}")

    def print_kerberoast(self):
        """Method to get infos about kerberoastable users.
        Log its sAMAccountName and servicePrincipalName"""
        search_filter = "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        search_attributes = ["cn", "samaccountname", "serviceprincipalname"]
        for kerberoastable_user in self.search(search_filter, search_attributes):
            self.__print_user_with_spn(kerberoastable_user)

    def get_kerberoast(self):
        """Method to get infos about kerberoastable users.
        Log its sAMAccountName and servicePrincipalName"""
        search_filter = "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        search_attributes = ["cn", "samaccountname", "serviceprincipalname"]
        return self.search(search_filter, search_attributes)

    def print_asreqroast(self):
        """Method to get all accounts that are vulnerable to ASREPRoast.
        Filter based on https://www.tarlogic.com/en/blog/how-to-attack-kerberos/"""
        search_filter = "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        search_attributes = ["cn", "samaccountname"]
        for asreqroastuser in self.search(search_filter, search_attributes):
            log_success(f"{asreqroastuser}")

    def print_search_spn(self, search_filter, size_limit=100):
        """Method to find services registered in the AD."""
        if not re.search("serviceprincipalname", search_filter, re.IGNORECASE):
            search_filter = f"(servicePrincipalName={search_filter}*)"
        search_attributes = ["cn", "samaccountname", "serviceprincipalname"]
        for spn_user in self.search(
            search_filter, search_attributes, size_limit=size_limit
        ):
            self.__print_user_with_spn(spn_user)

    def print_lastpwchangekrbtgt(self):
        """Method to retreive the last time the password for krbtgt was reset."""
        search_filter = "(cn=krbtgt)"
        search_attributes = ["pwdLastSet"]
        for krbtgt in self.search(search_filter, search_attributes):
            # when_changed = krbtgt['pwdLastSet'].replace(microsecond=0).isoformat()
            # this one is similar but easier to read
            when_changed = krbtgt["pwdLastSet"].strftime("%Y-%m-%d %H:%M:%S")
            log_info(f"krbtgt password changed at {when_changed}")

    def print_search_delegation(self):
        """Method to retreive accounts with TRUSTED_FOR_DELEGATION set in userAccountControl"""
        search_filter = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        search_attributes = ["samaccountname"]
        for account_trusted_for_delegation in self.search(
            search_filter, search_attributes
        ):
            log_success(f"{account_trusted_for_delegation['sAMAccountName']}")

    def print_creator_sid(self):
        """Main function to get info about createsid from ms-ds-creatorsid."""
        # get all createsid without parse
        search_filter = "(ms-ds-creatorsid=*)"
        search_attributes = ["sAMAccountName", "mS-DS-CreatorSID"]
        for asreqroastuser in self.search(search_filter, search_attributes):
            log_success(f"{asreqroastuser}")
            if asreqroastuser["mS-DS-CreatorSID"] != "":
                sid_str = convert_sid_to_string(asreqroastuser["mS-DS-CreatorSID"])
            log_info(sid_str)
            # parse objectSid
            search_filter_get_name = f"(objectSid={sid_str})"
            search_attributes_get_name = ["sAMAccountName"]
            asreqroastuser_get_name_obj = self.search(
                search_filter_get_name, search_attributes_get_name
            )
            if asreqroastuser_get_name_obj:
                for asreqroastuser_get_name in asreqroastuser_get_name_obj:
                    if asreqroastuser_get_name["sAMAccountName"] is not None:
                        log_info(
                            f'CreatorSID: {asreqroastuser_get_name["sAMAccountName"]}'
                        )
            else:
                log_error("Maybe already deleted")
