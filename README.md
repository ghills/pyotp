How to Use
==========

Standalone
----------
Invoke as a standalone OTP, 6 character, 30 second interval generator

1. echo TOPSECRETPWD | otp.py
2. otp.py secret.txt
3. otp.py < secret.txt

Module
------
See example/foo.py

```python
import otp
# get your secret

totp = otp.totp_code( secret, interval=60, digits=8 )
```
