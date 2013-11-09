#!/usr/bin/env python

"""
Simple HOTP and TOTP implementation.

Based on the following RFCs:
HOTP - RFC 4226 - http://tools.ietf.org/html/rfc4226
TOTP - RFC 6238 - http://tools.ietf.org/html/rfc6238
"""

import base64
import hashlib
import hmac
import struct
import time

def int_to_big_endian_bytes( val ):
    """
    Converts an integer to 8 byte array as a big endian value.
    HOTP spec calls out big endian inputs.
    """
    return bytearray( struct.pack('>Q',val) )

def sha1_digest( key, counter ):
    """Returns a bytearray of an HMAC SHA-1 digest"""
    return bytearray(hmac.new( key=key, msg=counter, digestmod=hashlib.sha1 ).digest())

def dynamic_truncation( hmac_result ):
    """
    Implements the hash dynamic truncation method described in
    RFC 4226.
    """
    # HMAC SHA-1 algorithm should output 20 bytes
    assert( len(hmac_result) == 20 )

    offset = hmac_result[19] & 0xF
    bin_code = ( hmac_result[offset] & 0x7F ) << 24     \
             | ( hmac_result[offset+1] & 0xFF ) << 16   \
             | ( hmac_result[offset+2] & 0xFF ) << 8    \
             | ( hmac_result[offset+3] & 0xFF )
    return bin_code

def otp_code( secret, counter, digits=6 ):
    """Returs OTP code based on secret and counter value"""

    if digits < 6 or digits > 8:
        # the RFC only allows 6-8 digits
        raise ValueError('Invalid number of digits: {}'.format(digits))

    secret_hash = base64.b32decode(secret)
    count_hash = int_to_big_endian_bytes(counter)
    digest = sha1_digest( key=secret_hash, counter=count_hash )
    bin_code = dynamic_truncation(digest)
    
    return ( bin_code % ( 10**digits ) )

def hotp_code( secret, counter, digits=6 ):
    """Gets the HOTP code"""
    return otp_code( secret, counter, digits )

def totp_code( secret, interval=30, digits=6, epoch_time=None ):
    """Gets the TOTP code"""
    if epoch_time is None:
        epoch_time = time.time()

    count = int( epoch_time / interval )
    return otp_code( secret, count, digits )

def main():
    import fileinput

    for line in fileinput.input():
        line = line.strip()
        try:
            print '{0:06d}'.format(totp_code(line))
        except TypeError:
            print 'Unable to decode {} as a based 32 string'.format(line)
            return -1

if __name__ == '__main__':
    main()

__author__ = "Gavin Hills"
