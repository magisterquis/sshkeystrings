SSH Key Strings
===============
Like [strings(1)](https://man.openbsd.org/strings), but only prints strings
which might be in an ssh private key.

The idea is to reasonably quickly scrape all of the SSH keys off of a disk.
Output's a bit messy, so expect to do some post-processing.

Should work on Linux and OpenBSD, at least.

Quickstart
----------
```sh
cc -O2 -o sshkeystrings sshkeystrings.c
./sshkeystrings /dev/xda1 > /dev/shm/found
-----BEGIN RSA PRIVATE KEY-----
MIIBxwIBAAJhAKD0YSHy73nUgysO13XsJmd4fHiFyQ+00R7VVu2iV9Qco
-----END RSA PRIVATE KEY-----
-----BEGIN RSA PRIVATE KEY-----
-----END RSA PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAkIpbeZ6b6NK26bi9HwKCBgrys29CjTFEOxhyHSXisnST7fY4QCDt
1dHxYn0rxGIGYBotLV19Jo0TKlvr+vPzaJVisLx22JFcBOZTAf2+9QSfng7EWM1uacKRul
...snip...
A1KegS4kff7FlfuSyMMNcbAvN71/YYV7Pm0TwGiuG4wu84E8wteslc934pxzQnH6fralJA
+AjwF2Q6u9Cce0yHLQJPlQIRV91NDyGukhm5y9C9AAWrRFRDfppj+PRPFTMoL9Ypw8iAU5
GYahV9wSGo6j0AAAAKcm9vdEBidWlsZAE=
-----END OPENSSH PRIVATE KEY-----
-----END OPENSSH PRIVATE KEY-----
-----BEGIN RSA PRIVATE KEY-----
YOUR-ORGS-VALIDATION-KEY-HERE
-----END RSA PRIVATE KEY-----
-----BEGIN RSA PRIVATE KEY-----
YOUR-ORGS-VALIDATION-KEY-HERE
```
