# ldapsearch-ad.py detailled usage

## -h could help

``` text
$ ./ldapsearch-ad.py -h                                                                      
usage: ldapsearch-ad.py [-h] [-l LDAP_SERVER] [-ssl] [-t REQUEST_TYPE] [-d DOMAIN] [-u USERNAME] [-p PASSWORD] [-H HASHES]
                        [-s SEARCH_FILTER] [-z SIZE_LIMIT] [-o OUTPUT_FILE] [-v] [--version]
                        [search_attributes ...]

Active Directory LDAP Enumerator

positional arguments:
  search_attributes     LDAP attributes to look for (default is all).

options:
  -h, --help            show this help message and exit
  -l LDAP_SERVER, --server LDAP_SERVER
                        IP address of the LDAP server.
  -ssl, --ssl           Force an SSL connection?.
  -t REQUEST_TYPE, --type REQUEST_TYPE
                        Request type: info, whoami, search, search-large, trusts, pass-pols, admins, show-user, show-user-list,
                        kerberoast, search-spn, asreproast, goldenticket, search-delegation, createsid, all
  -d DOMAIN, --domain DOMAIN
                        Authentication account's FQDN. Example: "contoso.local".
  -u USERNAME, --username USERNAME
                        Authentication account's username.
  -p PASSWORD, --password PASSWORD
                        Authentication account's password.
  -H HASHES, -hashes HASHES
                        NTLM hashes, format is LMHASH:NTHASH
  -s SEARCH_FILTER, --search-filter SEARCH_FILTER
                        Search filter (use LDAP format).
  -z SIZE_LIMIT, --size_limit SIZE_LIMIT
                        Size limit (default is 100, or server' own limit).
  -o OUTPUT_FILE, --output OUTPUT_FILE
                        Write results in specified file too.
  -v, --verbose         Turn on debug mode
  --version             Show version and exit

```

## Actions

### -t info

Retrieve server **information** without credentials using `-t info`.
Usefull to get the FQDN and the functionality levels.

``` text
$ ./ldapsearch-ad.py -l 192.168.56.20 -t info
Getting info from LDAP server 192.168.56.20
Forest functionality level = Windows 2012 R2
Domain functionality level = Windows 2012 R2
Domain controller functionality level = Windows 2012 R2
rootDomainNamingContext = DC=evilcorp,DC=lab2
defaultNamingContext = DC=evilcorp,DC=lab2
ldapServiceName = evilcorp.lab2:mtldc1$@EVILCORP.LAB2
naming_contexts = ['DC=evilcorp,DC=lab2', 'CN=Configuration,DC=evilcorp,DC=lab2', 'CN=Schema,CN=Configuration,DC=evilcorp,DC=lab2', 'DC=DomainDnsZones,DC=evilcorp,DC=lab2', 'DC=ForestDnsZones,DC=evilcorp,DC=lab2']
```

### -t whoami

Check authentication using `-t whoami`.
Usefull to attempt an authentication to verify a password.

``` text
$ ./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u bbilly -p 'P@$$w0rd' -t whoami
Executing whoami on LDAP server 192.168.56.20
You are: "u:EVILCORP\bbilly"
```

### -t trusts

List **trusts** attributes using `-t trusts` (user account needed).
Usefull to get a full view of the Active Directory overall architecture.

``` text
$ ./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -t trusts
Looking for trusts on LDAP server 192.168.56.20
Trust =
+ fra.evilcorp.lab2 (FRA)
|___trustAttributes = ['TRUST_ATTRIBUTE_WITHIN_FOREST']
|___trustDirection = Bidirectional
|___trustType = The trusted domain is a Windows domain running Active Directory.
|___trustPartner = fra.evilcorp.lab2
|___securityIdentifier = S-1-5-21-2894840767-735700-3593130334
|___whenCreated = 2019-03-09 04:57:15+00:00
|___whenChanged = 2019-03-09 04:57:15+00:00
```

### -t pass-pols

List **password policies** using `-t pass-pols` (user account needed for default password policy / admin account needed for fine grained password policies).
Usefull to prepare our next password spraying attack ;)

``` text
$ ./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -t pass-pols
Looking for all password policies on LDAP server 192.168.56.20
+ Default password policy:
|___Minimum password length = 7
|___Password complexity = Enabled
|___Lockout threshold = Disabled
No fine grained password policy found (high privileges are often required).
```

### -t admins

Show the **admins** (members of *domain admins*, *enterprise admins*, and *administrators*) and their most interesting flags using `-t admins` (user account needed).
Usefull to find juicy targets.

``` text
$ ./ldapsearch-ad.py -l 192.168.56.2 -d evilcorp.lab2 -u jjohnny -p 'P@$$word' -t admins     
### Result of "admins" command ###
[+] All members of group "Administrateurs":
[*]     admbilly (DONT_EXPIRE_PASSWORD)
[+]     Administrateur
[+] All members of group "Admins du domaine":
[+]     Administrateur
```

### -t show-user

Show the most interesting attributes of a user using `-t show-user` (user account needed).
Usefull to get more information about a juicy target.

``` text
$ ./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -t show-user -s '(samaccountname=bbilly)'
Looking for users on LDAP server 192.168.56.20
+ bbilly
|___type: user
|___The adminCount is set to 1
|___userAccountControl = ENCRYPTED_TEXT_PWD_ALLOWED, NORMAL_ACCOUNT
|___sAMAccountType = SAM_USER_OBJECT
|___memberOf = Bad admins
```

or even computers or groups. Everything depend of the search parameter `-s`.

``` text
$ ./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -t show-user -s '(samaccountname=mtldc1$)'
Looking for users on LDAP server 192.168.56.20
+ MTLDC1$
|___type: computer
|___userAccountControl = SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION
|___sAMAccountType = SAM_MACHINE_ACCOUNT

$ ./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -t show-user -s '(cn=bad admins)'
Looking for users on LDAP server 192.168.56.20
+ bad_admins
|___type: group
|___displayName = Bad Admins
|___The adminCount is set to 1
|___sAMAccountType = SAM_GROUP_OBJECT
|___memberOf = Domain Admins
```

### -t all

Retrieve all interesting information with a simple user account using `-t all`.

``` text
$ ./ldapsearch-ad.py -l 192.168.56.2 -d evilcorp.lab2 -u jjohnny -p 'P@$$word' -t all 
### Server infos ###
[+] Forest functionality level = Windows 2012 R2
[+] Domain functionality level = Windows 2012 R2
[+] Domain controller functionality level = Windows 2012 R2
[+] rootDomainNamingContext = DC=evilcorp,DC=lab2
[+] defaultNamingContext = DC=evilcorp,DC=lab2
[+] ldapServiceName = evilcorp.lab2:win2012-dc01$@EVILCORP.LAB2
[+] naming_contexts = ['DC=evilcorp,DC=lab2', 'CN=Configuration,DC=evilcorp,DC=lab2', 'CN=Schema,CN=Configuration,DC=evilcorp,DC=lab2', 'DC=DomainDnsZones,DC=evilcorp,DC=lab2', 'DC=ForestDnsZones,DC=evilcorp,DC=lab2']
### Result of "admins" command ###
All members of group "Administrateurs":
[+]     Administrateur
[*]     admbilly (DONT_EXPIRE_PASSWORD)
All members of group "Admins du domaine":
[+]     Administrateur
### Result of "pass-pols" command ###
Default password policy:
[+] |___Minimum password length = 7
[+] |___Password complexity = Enabled
[*] |___Lockout threshold = Disabled
[+] No fine grained password policy found (high privileges are required).
### Result of "trusts" command ###
### Result of "kerberoast" command ###
### Result of "asreqroast" command ###
### Result of "goldenticket" command ###
[+] [DN: CN=krbtgt,CN=Users,DC=evilcorp,DC=lab2 - STATUS: Read - READ TIME: 2022-07-24T17:49:27.744027
    whenChanged: 2022-07-23 20:34:12+00:00
]
### Result of "search-delegation" command ###
[*] DN: CN=WIN2012-DC01,OU=Domain Controllers,DC=evilcorp,DC=lab2 - STATUS: Read - READ TIME: 2022-07-24T17:49:27.745927
    cn: WIN2012-DC01
    sAMAccountName: WIN2012-DC01$

### Result of "creatorsid" command ###
```

### -t create-sid

Get info about createsid from ms-ds-creatorsid.

``` bash
./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -t createsid
```

## Authenticate with an NTLM hash instead of a password

Because sometimes the compromise is still on-going.

``` bash
./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -hashes :32ed87bdb5fdc5e9cba88547376818d4 -t show-admins
```

## Append output to a file

It is possible to append the output in a file by using `-o <filename>`.
For instance:

``` bash
./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -t info -o info_from_DC.log
```

## Advanced usage using search

Search for any information using the powerful ldap filter syntax with `-t search`:

``` text
$ ./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -t search -s '(&(objectClass=user)(servicePrincipalName=*))' cn serviceprincipalname
Searching on LDAP server 192.168.56.20
Entry = 
DN: CN=MTLDC1,OU=Domain Controllers,DC=evilcorp,DC=lab2 - STATUS: Read - READ TIME: 2019-03-09T19:40:12.086215
    cn: MTLDC1
    servicePrincipalName: Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/MTLDC1.evilcorp.lab2
                          ldap/MTLDC1.evilcorp.lab2/ForestDnsZones.evilcorp.lab2
                          ldap/MTLDC1.evilcorp.lab2/DomainDnsZones.evilcorp.lab2
                          DNS/MTLDC1.evilcorp.lab2
                          GC/MTLDC1.evilcorp.lab2/evilcorp.lab2
[…]
```
