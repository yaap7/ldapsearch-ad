# ldapsearch-ad.py

Python3 script to quickly get various information from a domain controller through his LDAP service.

## Quick RTFM

Basically, if you do not have valid credentials yet, you can only use:

``` bash
ldapsearch-ad.py -l 192.168.56.20 -t info
```

And once you get valid credentials, you will want to use `-all`:

``` bash
ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -t all
```

## Usage

Help:

```
$ ./ldapsearch-ad.py -h
usage: ldapsearch-ad.py [-h] -l LDAP_SERVER -t REQUEST_TYPE [-d DOMAIN]
                        [-u USERNAME] [-p PASSWORD] [-s SEARCH_FILTER]
                        [-z SIZE_LIMIT] [-o OUTPUT_FILE] [-v]
                        [search_attributes [search_attributes ...]]

Active Directory LDAP Enumerator

positional arguments:
  search_attributes     LDAP attributes to look for.

optional arguments:
  -h, --help            show this help message and exit
  -l LDAP_SERVER, --server LDAP_SERVER
                        IP address of the LDAP server.
  -t REQUEST_TYPE, --type REQUEST_TYPE
                        Request type: info, whoami, search, trusts, pass-pols,
                        show-domain-admins, show-user, auto
  -d DOMAIN, --domain DOMAIN
                        Authentication account's FQDN. Example:
                        "contoso.local".
  -u USERNAME, --username USERNAME
                        Authentication account's username.
  -p PASSWORD, --password PASSWORD
                        Authentication account's password.
  -s SEARCH_FILTER, --search-filter SEARCH_FILTER
                        Search filter (use LDAP format).
  -z SIZE_LIMIT, --size_limit SIZE_LIMIT
                        Size limit (default is server's limit).
  -o OUTPUT_FILE, --output OUTPUT_FILE
                        Write results in specified file too.
  -v, --verbose         Turn on debug mode
```


Retrieve server **information** without credentials using `-t info`:

```
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

Check authentication using `-t whoami`:

```
$ ./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u bbilly -p 'P@$$w0rd' -t whoami
Executing whoami on LDAP server 192.168.56.20
You are: "u:EVILCORP\bbilly"
```

List **trusts** attributes using `-t trusts` (user account needed):

```
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

List **password policies** using `-t pass-pols` (user account needed for default password policy / admin account needed for fine grained password policies):

```
$ ./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -t pass-pols
Looking for all password policies on LDAP server 192.168.56.20
+ Default password policy:
|___Minimum password length = 7
|___Password complexity = Enabled
|___Lockout threshold = Disabled
No fine grained password policy found (high privileges are often required).
```

Show the **domain admins** and their most interesting flags using `-t show-domain-admins` (user account needed):

```
$ ./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -t show-domain-admins
Looking for domain admins on LDAP server 192.168.56.20
Domain admin group's distinguishedName = CN=Domain Admins,CN=Users,DC=evilcorp,DC=lab2 
3 domain admins found:
+ Administrator
+ bbilly (ENCRYPTED_TEXT_PWD_ALLOWED)
+ dhcp_service
```

Show the most interesting attributes of a user using `-t show-user` (user account needed):

```
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

```
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

Retrieve all interesting information with a simple user account using `-t auto`:

```
$ ./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -t auto
###  Server Info  ###
Getting info from LDAP server 192.168.56.20
Forest functionality level = Windows 2012 R2
Domain functionality level = Windows 2012 R2
Domain controller functionality level = Windows 2012 R2
rootDomainNamingContext = DC=evilcorp,DC=lab2
defaultNamingContext = DC=evilcorp,DC=lab2
ldapServiceName = evilcorp.lab2:mtldc1$@EVILCORP.LAB2
naming_contexts = ['DC=evilcorp,DC=lab2', 'CN=Configuration,DC=evilcorp,DC=lab2', 'CN=Schema,CN=Configuration,DC=evilcorp,DC=lab2', 'DC=DomainDnsZones,DC=evilcorp,DC=lab2', 'DC=ForestDnsZones,DC=evilcorp,DC=lab2']
###  List of Domain Admins  ###
Looking for domain admins on LDAP server 192.168.56.20
Domain admin group's distinguishedName = CN=Domain Admins,CN=Users,DC=evilcorp,DC=lab2 
3 domain admins found:
+ Administrator
+ bbilly (ENCRYPTED_TEXT_PWD_ALLOWED)
+ dhcp_service
###  List of Trusts  ###
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
###  Details of Password Policies  ###
Looking for all password policies on LDAP server 192.168.56.20
+ Default password policy:
|___Minimum password length = 7
|___Password complexity = Enabled
|___Lockout threshold = Disabled
No fine grained password policy found (high privileges are often required).
```

## Advanced usage using search

Search for any information using the powerfull ldap filter syntax with `-t search`:

```
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


## TODO

* [ ] give usefull `search` examples (see https://phonexicum.github.io/infosec/windows.html and https://blog.xpnsec.com/kerberos-attacks-part-2/) ;
* [ ] add pretty output for other functions (get-user, get-spn, etc) while keeping a json output ;
* [ ] add a command to get users vulnerables to AS-REP-roasting
* [ ] implement a search for ForeignSecurityPrincipals (When a user/group from an *external* domain/forest are added to a group in a domain, an object of type foreignSecurityPrincipal is created at `CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`)
* [ ] implement ldap3 pagging functionality
* [ ] continuously improve this documentation

for v2:

* [x] change the core architecture to create an object and do not open multiple connection for `-t all`


## Credits

Thanks to [Bengui](https://youtu.be/xKG9v0UfuH0?t=228) for the username convention.

