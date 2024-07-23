# ldapsearch-ad.py

![Python version](https://img.shields.io/badge/python-v3.6+-informational)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Code linter: flake8](https://img.shields.io/badge/Code%20linter-flake8-blue)](https://github.com/PyCQA/flake8)

![GitHub Repo stars](https://img.shields.io/github/stars/yaap7/ldapsearch-ad?style=social)
![GitHub Repo forks](https://img.shields.io/github/forks/yaap7/ldapsearch-ad?style=social)

![PyPI version](https://img.shields.io/pypi/v/ldapsearchad)
![PyPI format](https://img.shields.io/pypi/format/ldapsearchad)
![PyPI license](https://img.shields.io/pypi/l/ldapsearchad)

Python3 script to quickly get various information from a domain controller through its LDAP service.

I'm used to launch it as soon as I get valid AD credentials, while [BloodHound](https://github.com/BloodHoundAD/BloodHound) and [PingCastle](https://www.pingcastle.com/) are processing.

## Requirements

* Python version 3.6 or above is required to use f-Strings.
* `ldap3`: to connect to the ldap service of target domain controller
* `pycryptodome`: to connect using hash instead of password

## Installation

With `pipx`:

```bash
pipx install git+https://github.com/yaap7/ldapsearch-ad
```

Simply get the source code and install the requirements:

``` bash
git clone https://github.com/yaap7/ldapsearch-ad.git
cd ldapsearch-ad
pip install -r ./requirements.txt
```

## Quick RTFM

Basically, if you do not have valid credentials yet, you can only use:

``` bash
ldapsearch-ad.py -l 192.168.56.20 -t info
```

And once you get valid credentials, you will want to use `-all` with the logging option to get back to results later:

``` bash
ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -o evilcorp_discover_all.log -t all
```

Thanks to [Like0x](https://github.com/Like0x) from [P1-Team](https://github.com/P1-Team), it is now possible to use it even with the hash:

``` bash
./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -hashes :32ed87bdb5fdc5e9cba88547376818d4 -t show-admins
```

More examples can be found in [USAGE.md](USAGE.md).

## TODO

* [ ] Adapt the package so it could be used independently (in CLI or as a package to import)
* [ ] look for new vulnerable configuration to add: <https://youtu.be/7_iv_eaAFyQ>

Done:

* [x] publish *ldapsearchad* as a package on [PyPI](https://pypi.org/project/ldapsearchad/).
* [x] create a python package to help other projects to import the functions and use the main class.
* [x] implement ldap3 pagging functionality: available since [v2022.08.18](https://github.com/yaap7/ldapsearch-ad/releases/tag/v2022.08.18)
* [x] verify all the `-t` options are shown in [USAGE.md](USAGE.md) and explain most complicated options : kerberoast, search-spn, asreproast, goldenticket, search-delegation, createsid.
* [x] give useful `search` examples (see <https://phonexicum.github.io/infosec/windows.html> and <https://blog.xpnsec.com/kerberos-attacks-part-2/>)
* [x] add a command to get vulnerable users to AS-REP-roasting (thanks [@HadrienPerrineau](https://github.com/HadrienPerrineau))
* [x] change the core architecture to create an object and do not open multiple connection for `-t all`
* [x] search for ForeignSecurityPrincipals (When a user/group from an *external* domain/forest are added to a group in a domain, an object of type foreignSecurityPrincipal is created at `CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`)

## Contributions

Feel free to fork, adapt, modify, contribute, and do not hesitate to send a pull request so the tool could be improved for everyone.

I would even make you a [collaborator](https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-github-user-account/managing-access-to-your-personal-repositories/inviting-collaborators-to-a-personal-repository) if you want so you could contribute directly on this repo!

### Contributors

* [CSbyGB](https://github.com/CSbyGB) for typos corrections
* [Like0x](https://github.com/Like0x) from [P1-Team](https://github.com/P1-Team) for the connection using NTLM hash instead of password, and the `createsid` feature.
* [nsilver7](https://github.com/nsilver7) for the option to append the output in a file in addition to the standard output.
* [d34dl0ckk](https://github.com/d34dl0ckk) for adding the `-n` option to request data from the Global Catalog, and the `-t search-foreign-security-principals` feature.
* [Adamkadaban](https://github.com/Adamkadaban) for improving the OpSec of the tool by getting sensitive information (login, password, hash) from files instead in the CLI directly, and by adding `setup.py` to allow easy installation through `pipx`! 🎊
* [DrorDvash](https://github.com/DrorDvash) for reporting a bug in `-t goldenticket`.

## Credits

Obviously, all credits goes to people who discover the technics and vulnerabilities.
This tool is only an humble attempt to implement their technics using python3 to understand how things work and because I like to play with the LDAP interface of Active Directory.
Unfortunately, I heard the ldap interface could be removed from domain controllers in the future :(

Thanks to [Bengui](https://youtu.be/xKG9v0UfuH0?t=228) for the username convention.

## Similar projects

* <https://github.com/Processus-Thief/HEKATOMB>
* <https://github.com/skelsec>
