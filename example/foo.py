import otp

secret = '3ORMAAI2NRT7OGA6'

print otp.totp_code(secret)
print otp.hotp_code(secret,982391)
