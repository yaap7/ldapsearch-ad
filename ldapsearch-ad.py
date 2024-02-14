#!/usr/bin/env python3

import argparse
import logging

from sys import exit
from sys import stdout

from os import path as os_path

from ldapsearchad import LdapsearchAd
from ldapsearchad import version as ldapsearchad_version

from ldapsearchad.logging import log_title
from ldapsearchad.logging import log_error
from ldapsearchad.logging import log_info

from ldapsearchad.utils import list_uac_flags
from ldapsearchad.utils import str_samaccounttype


def main():
    # Parse arguments
    arg_parser = argparse.ArgumentParser(description="Active Directory LDAP Enumerator")
    arg_parser.add_argument(
        "-l", "--server", dest="ldap_server", help="IP address of the LDAP server."
    )
    arg_parser.add_argument(
        "-n",
        "--port",
        dest="server_port_number",
        type=int,
        help="Port number to request (389 (LDAP), 636 (LDAP over SSL), 3268 (GC), 3269 (GC over SSL)).",
    )
    arg_parser.add_argument(
        "-ssl",
        "--ssl",
        dest="ssl",
        action="store_true",
        help="Force an SSL connection?.",
    )
    arg_parser.add_argument(
        "-t",
        "--type",
        dest="request_type",
        help="Request type: info, whoami, search, csv, trusts,\
        pass-pols, admins, show-user, show-user-list, kerberoast, search-spn, asreproast, goldenticket,\
        search-delegation, createsid, search-foreign-security-principals, all",
    )
    arg_parser.add_argument(
        "-d",
        "--domain",
        dest="domain",
        help='Authentication account\'s FQDN. Example: "contoso.local".',
    )
    arg_parser.add_argument(
        "-u", "--username", dest="username", help="Authentication account's username."
    )
    arg_parser.add_argument(
        "-p", "--password", dest="password", help="Authentication account's password."
    )
    arg_parser.add_argument(
        "-H", "-hashes", dest="hashes", help="NTLM hashes, format is LMHASH:NTHASH"
    )
    arg_parser.add_argument(
        "-s",
        "--search-filter",
        dest="search_filter",
        help="Search filter (use LDAP format and don't forget parenthesis).",
    )
    arg_parser.add_argument(
        "search_attributes",
        default="*",
        nargs="*",
        help="LDAP attributes to look for (default is all).",
    )
    arg_parser.add_argument(
        "-z",
        "--size_limit",
        dest="size_limit",
        default=100,
        help="Size limit (default is 100).",
    )
    arg_parser.add_argument(
        "-o",
        "--output",
        dest="output_file",
        help="Write results in specified file too.",
    )
    arg_parser.add_argument(
        "-v",
        "--verbose",
        dest="verbosity",
        help="Turn on debug mode",
        action="store_true",
    )
    arg_parser.add_argument(
        "--version",
        dest="ask_for_version",
        help="Show version and exit",
        action="store_true",
    )
    args = arg_parser.parse_args()

    if args.ask_for_version:
        print(f"ldapsearchad v{ldapsearchad_version()}")
        exit(0)

    # if the version is not asked, we should have at least a target and an action
    if args.ldap_server is None or args.request_type is None:
        arg_parser.error("-l/--server and -t/--type are mandatory arguments.")

    # Set mandatory arguments for each request_type
    mandatory_arguments = {}
    mandatory_arguments["info"] = []
    mandatory_arguments["whoami"] = ["domain", "username"]
    mandatory_arguments["search"] = ["domain", "username", "search_filter"]
    mandatory_arguments["csv"] = [
        "domain",
        "username",
        "search_filter",
        "search_attributes",
    ]
    mandatory_arguments["show-user"] = ["domain", "username", "search_filter"]
    mandatory_arguments["show-user-list"] = ["domain", "username", "search_filter"]
    mandatory_arguments["member-of"] = ["domain", "username", "search_filter"]
    mandatory_arguments["user-of"] = ["domain", "username", "search_filter"]
    mandatory_arguments["trusts"] = ["domain", "username"]
    mandatory_arguments["pass-pols"] = ["domain", "username"]
    mandatory_arguments["admins"] = ["domain", "username"]
    mandatory_arguments["kerberoast"] = ["domain", "username"]
    mandatory_arguments["asreproast"] = ["domain", "username"]
    mandatory_arguments["search-spn"] = ["domain", "username", "search_filter"]
    mandatory_arguments["goldenticket"] = ["domain", "username"]
    mandatory_arguments["search-delegation"] = ["domain", "username"]
    mandatory_arguments["createsid"] = ["domain", "username"]
    mandatory_arguments["search-foreign-security-principals"] = ["domain", "username"]
    mandatory_arguments["all"] = ["domain", "username"]
    actions = [i.strip() for i in args.request_type.split(",")]
    for action in actions:
        if action not in mandatory_arguments.keys():
            arg_parser.error(
                f'request type must be one of: {", ".join(mandatory_arguments.keys())}.'
            )
        for mandatory_argument in mandatory_arguments[action]:
            if vars(args)[mandatory_argument] is None:
                arg_parser.error(
                    f"{mandatory_argument} argument is mandatory with request type = {action}"
                )

    # Configure logging to stdout
    logger = logging.getLogger()
    logger.removeHandler(logger.handlers[0])
    handler = logging.StreamHandler(stdout)
    if args.verbosity:
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            fmt="%(asctime)-19s %(levelname)-8s %(message)s",
            datefmt="%Y-%m-%d_%H:%M:%S",
        )
    else:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter(fmt="%(message)s")
    handler.setFormatter(formatter)
    if args.output_file:
        f_handler = logging.FileHandler(args.output_file)
        f_handler.setFormatter(formatter)
        logger.addHandler(f_handler)
    logger.addHandler(handler)

    # Read username, password, and hashes from file if it exists
    def read_from_file_if_exists(arg):
        if arg is not None and os_path.isfile(arg):
            with open(arg) as fin:
                return fin.readline().rstrip()
        else:
            return arg

    # Connection to the LDAP server using credentials provided in argument
    ldap = LdapsearchAd(
        args.ldap_server,
        args.server_port_number,
        args.ssl,
        args.domain,
        read_from_file_if_exists(args.username),
        read_from_file_if_exists(args.password),
        read_from_file_if_exists(args.hashes),
    )

    for action in actions:

        # Get the server's infos
        if action == "info":
            log_title("Server infos", 3)
            ldap.infos()

        # Check the connection and retrieve the username used for the connection
        elif action == "whoami":
            log_title('Result of "whoami" command', 3)
            ldap.whoami()

        # Raw search
        elif action == "search":
            excluded_attributes = [
                "dSCorePropagationData",
                "mSMQDigests",
                "mSMQSignCertificates",
                "userCertificate",
                "uSNCreated",
                "uSNChanged",
            ]
            log_title('Result of "search" command', 3)
            entries = ldap.search(
                args.search_filter, args.search_attributes, args.size_limit
            )
            for entry in entries:
                attributes = sorted(
                    [i for i in entry.keys() if i not in excluded_attributes]
                )
                for attribute in attributes:
                    if attribute == "userAccountControl":
                        log_info(
                            f"|__ {attribute} = {', '.join(list_uac_flags(entry[attribute]))}"
                        )
                    elif attribute == "sAMAccountType":
                        log_info(
                            f"|__ {attribute} = {str_samaccounttype(entry[attribute])}"
                        )
                    else:
                        log_info(f"|__ {attribute} = {entry[attribute]}")

        # CSV export
        elif action == "csv":
            attributes = args.search_attributes
            print(",".join(attributes))
            entries = ldap.search(
                args.search_filter, args.search_attributes, args.size_limit
            )
            for entry in entries:
                values = []
                for attribute in attributes:
                    if attribute.lower() == "useraccountcontrol":
                        value = f'"{",".join(list_uac_flags(entry[attribute]))}"'
                    else:
                        value = str(entry[attribute])
                    values.append(value)
                try:
                    print(",".join(values))
                except TypeError as e:
                    print(f"type de values = {type(values)}")
                    print(f"values = {values}")
                    raise e

        # Get users
        elif action == "show-user":
            log_title('Result of "show-user" command', 3)
            ldap.print_users(
                args.search_filter, args.search_attributes, args.size_limit
            )

        # Get users list
        elif action == "show-user-list":
            log_title('Result of "show-user" command', 3)
            ldap.print_users_list(
                args.search_filter, args.search_attributes, args.size_limit
            )

        # Get users list of member of the specified group
        # search_filter should only contain the groupe name
        # then it is converted to a correct ldap filter
        elif action == "member-of":
            log_title('Result of "member-of" command', 3)
            if "(" in args.search_filter:
                logging.error(
                    'You must enter a group CN instead of a full search filter. (e.g. -s "Domain admins")'
                )
            else:
                ldap.print_member_of(args.search_filter, args.size_limit)

        # Get the list of groups whom the user is member of
        elif action == "user-of":
            log_title('Result of "user-of" command', 3)
            ldap.print_user_of(args.search_filter, args.size_limit)

        # Get list of Foreign Security Principals added to domain local groups from external/forest trusts
        elif action == "search-foreign-security-principals":
            log_title('Result of "search-foreign-security-principals" command', 3)
            ldap.print_search_foreign_security_principals(args.size_limit)

        # Get trusts
        elif action == "trusts":
            log_title('Result of "trusts" command', 3)
            ldap.print_trusts()

        # Get password policies
        elif action == "pass-pols":
            log_title('Result of "pass-pols" command', 3)
            ldap.print_pass_pols()

        # Get admins
        elif action == "admins":
            log_title('Result of "admins" command', 3)
            ldap.print_admins()

        # Get kerberoastable users accounts
        elif action == "kerberoast":
            log_title('Result of "kerberoast" command', 3)
            ldap.print_kerberoast()

        # Get ASRepRoast user account
        elif action == "asreproast":
            log_title('Result of "asreproast" command', 3)
            ldap.print_asreqroast()

        elif action == "search-spn":
            log_title('Result of "search-spn" command', 3)
            ldap.print_search_spn(args.search_filter, args.size_limit)

        elif action == "goldenticket":
            log_title('Result of "goldenticket" command', 3)
            ldap.print_lastpwchangekrbtgt()

        elif action == "search-delegation":
            log_title('Result of "search-delegation" command', 3)
            ldap.print_search_delegation()

        elif action == "createsid":
            log_title('Result of "createsid" command', 3)
            ldap.print_creator_sid()

        # Run all checks
        elif action == "all":
            log_title("Server infos", 3)
            ldap.infos()
            log_title('Result of "trusts" command', 3)
            ldap.print_trusts()
            log_title('Result of "pass-pols" command', 3)
            ldap.print_pass_pols()
            log_title('Result of "admins" command', 3)
            ldap.print_admins()
            log_title('Result of "kerberoast" command', 3)
            ldap.print_kerberoast()
            log_title('Result of "asreqroast" command', 3)
            ldap.print_asreqroast()
            log_title('Result of "goldenticket" command', 3)
            ldap.print_lastpwchangekrbtgt()

        else:
            log_error(
                "Error: This functionnality is not implemented yet. Please implement it now."
            )


if __name__ == "__main__":
    main()
