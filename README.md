Siemens LOGO!8 Information Gatherer (SLIG)
====

This script allows viewing the user profile setting which contains further access details and associated passwords as well as the program password. The author is Manuel Stotz (SySS GmbH).

You can find further details about those security issues in our SySS security advisories SYSS-2019-012, SYSS-2019-013, SYSS-2019-014 [1-3], and the Siemens Security Advisory SSA-542701[4].

[1] SySS Security Advisory SYSS-2019-012
<https://www.syss.de/fileadmin/dokumente/Publikationen/Advisories/SYSS-2019-012.txt>

[2] SySS Security Advisory SYSS-2019-013
<https://www.syss.de/fileadmin/dokumente/Publikationen/Advisories/SYSS-2019-013.txt>

[3] SySS Security Advisory SYSS-2019-014
<https://www.syss.de/fileadmin/dokumente/Publikationen/Advisories/SYSS-2019-014.txt>

[4] Siemens Security Advisory SSA-542701
<https://cert-portal.siemens.com/productcert/pdf/ssa-542701.pdf>

Usage
-----

Run it like this:

```
nmap --script slig.nse -p 10005 <IP|Host>
```

Demo
----

Watch the demo here:
<https://youtu.be/TpH4EABGYCs>

Requirements
------------

* `nmap`
* `key (see slig.nse)`

Disclaimer
----------

Use at your own risk. Do not use without full consent of everyone involved.
For educational purposes only.
