import codecs
import datetime
import struct

from .colors import c_green
from .colors import c_orange
from .colors import c_red
from .colors import c_white_on_red
from .colors import c_cyan
from .colors import c_purple


def str_human_date(date):
    # ldap3 version 2.6 returns a datetime.timedelta object
    if isinstance(date, datetime.timedelta):
        nb_sec = int(date.total_seconds())
    # older versions return a negative big number
    else:
        nb_sec = int((-date) / 10000000)
    if nb_sec > 60:
        nb_min = int(nb_sec / 60)
        nb_sec = nb_sec % 60
        if nb_min > 60:
            nb_hour = int(nb_min / 60)
            nb_min = nb_min % 60
            if nb_hour > 24:
                nb_day = int(nb_hour / 24)
                nb_hour = nb_hour % 24
                return f"{nb_day} days, {nb_hour} hours, {nb_min} minutes, {nb_sec} seconds"
            return f"{nb_hour} hours, {nb_min} minutes, {nb_sec} seconds"
        return f"{nb_min} minutes, {nb_sec} seconds"
    return f"{nb_sec} seconds"


def str_functionality_level(num):
    """Return the functionality level as described at:
    <https://msdn.microsoft.com/en-us/library/cc223274.aspx>
    Note: it is the same for forest, domain, and domain controller."""
    n = int(num)
    func_levels = [
        c_white_on_red("Windows 2000"),
        c_white_on_red("Windows 2003 with mixed domains"),
        c_white_on_red("Windows 2003"),
        c_red("Windows 2008"),
        c_red("Windows 2008 R2"),
        c_orange("Windows 2012"),
        c_orange("Windows 2012 R2"),
        c_green("Windows 2016"),
    ]
    if 0 <= n < len(func_levels):
        return func_levels[n]
    else:
        return f"Not known, update this script. (value = {num})"


def is_flag_in_uac(flag, uac):
    """Return a list of property flags as described at:
    <https://support.microsoft.com/en-gb/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro>
    """
    flags = {
        "SCRIPT": 0x1,
        "ACCOUNTDISABLE": 0x2,
        "HOMEDIR_REQUIRED": 0x8,
        "LOCKOUT": 0x10,
        "PASSWD_NOTREQD": 0x20,
        "PASSWD_CANT_CHANGE": 0x40,
        "ENCRYPTED_TEXT_PWD_ALLOWED": 0x80,
        "TEMP_DUPLICATE_ACCOUNT": 0x100,
        "NORMAL_ACCOUNT": 0x200,
        "INTERDOMAIN_TRUST_ACCOUNT": 0x800,
        "WORKSTATION_TRUST_ACCOUNT": 0x1000,
        "SERVER_TRUST_ACCOUNT": 0x2000,
        "DONT_EXPIRE_PASSWORD": 0x10000,
        "MNS_LOGON_ACCOUNT": 0x20000,
        "SMARTCARD_REQUIRED": 0x40000,
        "TRUSTED_FOR_DELEGATION": 0x80000,
        "NOT_DELEGATED": 0x100000,
        "USE_DES_KEY_ONLY": 0x200000,
        "DONT_REQ_PREAUTH": 0x400000,
        "PASSWORD_EXPIRED": 0x800000,
        "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x1000000,
        "PARTIAL_SECRETS_ACCOUNT": 0x04000000,
    }
    return uac & flags[flag] > 0


def list_uac_flags(uac):
    """Return a list of property flags as described at:
    <https://support.microsoft.com/en-gb/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro>
    """
    flags = []
    if uac & 0x1 > 0:
        flags.append("SCRIPT")
    if uac & 0x2 > 0:
        flags.append("ACCOUNTDISABLE")
    if uac & 0x8 > 0:
        flags.append("HOMEDIR_REQUIRED")
    if uac & 0x10 > 0:
        flags.append("LOCKOUT")
    if uac & 0x20 > 0:
        flags.append("PASSWD_NOTREQD")
    if uac & 0x40 > 0:
        flags.append("PASSWD_CANT_CHANGE")
    if uac & 0x80 > 0:
        flags.append("ENCRYPTED_TEXT_PWD_ALLOWED")
    if uac & 0x100 > 0:
        flags.append("TEMP_DUPLICATE_ACCOUNT")
    if uac & 0x200 > 0:
        flags.append("NORMAL_ACCOUNT")
    if uac & 0x800 > 0:
        flags.append("INTERDOMAIN_TRUST_ACCOUNT")
    if uac & 0x1000 > 0:
        flags.append("WORKSTATION_TRUST_ACCOUNT")
    if uac & 0x2000 > 0:
        flags.append("SERVER_TRUST_ACCOUNT")
    if uac & 0x10000 > 0:
        flags.append("DONT_EXPIRE_PASSWORD")
    if uac & 0x20000 > 0:
        flags.append("MNS_LOGON_ACCOUNT")
    if uac & 0x40000 > 0:
        flags.append("SMARTCARD_REQUIRED")
    if uac & 0x80000 > 0:
        flags.append("TRUSTED_FOR_DELEGATION")
    if uac & 0x100000 > 0:
        flags.append("NOT_DELEGATED")
    if uac & 0x200000 > 0:
        flags.append("USE_DES_KEY_ONLY")
    if uac & 0x400000 > 0:
        flags.append("DONT_REQ_PREAUTH")
    if uac & 0x800000 > 0:
        flags.append("PASSWORD_EXPIRED")
    if uac & 0x1000000 > 0:
        flags.append("TRUSTED_TO_AUTH_FOR_DELEGATION")
    if uac & 0x04000000 > 0:
        flags.append("PARTIAL_SECRETS_ACCOUNT")
    return flags


def list_uac_colored_flags(uac):
    """Return a list of property flags as described at:
    <https://support.microsoft.com/en-gb/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro>
    """
    flags = []
    if uac & 0x1 > 0:
        flags.append("SCRIPT")
    if uac & 0x2 > 0:
        flags.append(c_cyan("ACCOUNTDISABLE"))
    if uac & 0x8 > 0:
        flags.append("HOMEDIR_REQUIRED")
    if uac & 0x10 > 0:
        flags.append(c_orange("LOCKOUT"))
    if uac & 0x20 > 0:
        flags.append(c_white_on_red("PASSWD_NOTREQD"))
    if uac & 0x40 > 0:
        flags.append(c_red("PASSWD_CANT_CHANGE"))
    if uac & 0x80 > 0:
        flags.append(c_white_on_red("ENCRYPTED_TEXT_PWD_ALLOWED"))
    if uac & 0x100 > 0:
        flags.append("TEMP_DUPLICATE_ACCOUNT")
    if uac & 0x200 > 0:
        flags.append("NORMAL_ACCOUNT")
    if uac & 0x800 > 0:
        flags.append(c_cyan("INTERDOMAIN_TRUST_ACCOUNT"))
    if uac & 0x1000 > 0:
        flags.append(c_cyan("WORKSTATION_TRUST_ACCOUNT"))
    if uac & 0x2000 > 0:
        flags.append(c_cyan("SERVER_TRUST_ACCOUNT"))
    if uac & 0x10000 > 0:
        flags.append(c_red("DONT_EXPIRE_PASSWORD"))
    if uac & 0x20000 > 0:
        flags.append("MNS_LOGON_ACCOUNT")
    if uac & 0x40000 > 0:
        flags.append("SMARTCARD_REQUIRED")
    if uac & 0x80000 > 0:
        flags.append(c_orange("TRUSTED_FOR_DELEGATION"))
    if uac & 0x100000 > 0:
        flags.append("NOT_DELEGATED")
    if uac & 0x200000 > 0:
        flags.append(c_red("USE_DES_KEY_ONLY"))
    if uac & 0x400000 > 0:
        flags.append(c_red("DONT_REQ_PREAUTH"))
    if uac & 0x800000 > 0:
        flags.append(c_cyan("PASSWORD_EXPIRED"))
    if uac & 0x1000000 > 0:
        flags.append(c_orange("TRUSTED_TO_AUTH_FOR_DELEGATION"))
    if uac & 0x04000000 > 0:
        flags.append("PARTIAL_SECRETS_ACCOUNT")
    return flags


def str_samaccounttype(sat):
    """Return the SAM-Account-Type as described at:
    <https://docs.microsoft.com/en-us/windows/desktop/adschema/a-samaccounttype>"""
    if sat == 0x0:
        return "SAM_DOMAIN_OBJECT"
    elif sat == 0x10000000:
        return "SAM_GROUP_OBJECT"
    elif sat == 0x10000001:
        return "SAM_NON_SECURITY_GROUP_OBJECT"
    elif sat == 0x20000000:
        return "SAM_ALIAS_OBJECT"
    elif sat == 0x20000001:
        return "SAM_NON_SECURITY_ALIAS_OBJECT"
    elif sat == 0x30000000:
        return "SAM_USER_OBJECT"
    elif sat == 0x30000000:
        return "SAM_NORMAL_USER_ACCOUNT"
    elif sat == 0x30000001:
        return "SAM_MACHINE_ACCOUNT"
    elif sat == 0x30000002:
        return "SAM_TRUST_ACCOUNT"
    elif sat == 0x40000000:
        return "SAM_APP_BASIC_GROUP"
    elif sat == 0x40000001:
        return "SAM_APP_QUERY_GROUP"
    elif sat == 0x7FFFFFFF:
        return "SAM_ACCOUNT_TYPE_MAX"
    else:
        return c_purple("Error: unknown value")


def str_object_type(entry):
    if "sAMAccountType" in entry:
        sat = entry["sAMAccountType"]
        if sat == 0x0:
            return "domain"
        elif sat == 0x10000000:
            return "group"
        elif sat == 0x20000000:
            return "alias"
        elif sat == 0x30000000:
            return "user"
        elif sat == 0x30000001:
            return "computer"
        else:
            return c_purple(f"sAMAccountType = {sat}. Please complete this script.")
    else:
        return c_purple("Unable to find correct type (sAMAccountType not present).")


def list_trust_type(trust_type):
    """Return the trust type as defined here: <https://msdn.microsoft.com/en-us/library/cc223771.aspx>"""
    if trust_type == 1:
        return "The trusted domain is a Windows domain not running Active Directory."
    elif trust_type == 2:
        return "The trusted domain is a Windows domain running Active Directory."
    elif trust_type == 3:
        return "The trusted domain is running a non-Windows, RFC4120-compliant Kerberos distribution."
    elif trust_type == 4:
        return "Historical reference; this value is not used in Windows."
    else:
        return "Error: unknown value."


def list_trust_direction(trust_direction):
    """Return the trust direction as defined here: <https://msdn.microsoft.com/en-us/library/cc223768.aspx>"""
    if trust_direction == 0:
        return "Disabled"
    elif trust_direction == 1:
        return c_green("Outbound")
    elif trust_direction == 2:
        return c_green("Inbound")
    elif trust_direction == 3:
        return c_cyan("Bidirectional")
    else:
        return c_purple("Error: unknown value.")


def list_trust_attributes(ta):
    """Return the trust attribute flags as defined here: <https://msdn.microsoft.com/en-us/library/cc223779.aspx>"""
    flags = []
    if ta & 0x1 > 0:
        flags.append("TRUST_ATTRIBUTE_NON_TRANSITIVE")
    if ta & 0x2 > 0:
        flags.append("TRUST_ATTRIBUTE_UPLEVEL_ONLY")
    if ta & 0x4 > 0:
        flags.append("TRUST_ATTRIBUTE_QUARANTINED_DOMAIN")
    if ta & 0x8 > 0:
        flags.append("TRUST_ATTRIBUTE_FOREST_TRANSITIVE")
    if ta & 0x10 > 0:
        flags.append("TRUST_ATTRIBUTE_CROSS_ORGANIZATION")
    if ta & 0x20 > 0:
        flags.append("TRUST_ATTRIBUTE_WITHIN_FOREST")
    if ta & 0x40 > 0:
        flags.append("TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL")
    if ta & 0x80 > 0:
        flags.append("TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION")
    if ta & 0x200 > 0:
        flags.append("TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION")
    if ta & 0x400 > 0:
        flags.append("TRUST_ATTRIBUTE_PIM_TRUST")
    return flags


def convert_sid_to_string(hexstr):
    value = codecs.encode(bytes(hexstr[0]), "hex")
    init_value = bytes(hexstr[0])
    value = "S-1-5"
    for i in range(8, len(init_value), 4):
        value += f'-{str(struct.unpack("<I", init_value[i:i+4])[0])}'
    return value
