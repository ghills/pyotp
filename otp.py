#!/usr/bin/env python

"""
Simple HOTP and TOTP implementation.

Based on the following RFCs:
HOTP - RFC 4226 - http://tools.ietf.org/html/rfc4226
TOTP - RFC 6238 - http://tools.ietf.org/html/rfc6238
"""

import hashlib
import hmac
import struct

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

def hotp_code( secret, counter, digits=6 ):
    """Gets the HOTP code"""
    if digits < 6 or digits > 8:
        # the RFC only allows 6-8 digits
        raise Exception('Invalid number of digits: {}'.format(digits))

    count_hash = int_to_big_endian_bytes(counter)
    digest = sha1_digest(key=secret,counter=count_hash)
    bin_code = dynamic_truncation(digest)
    return ( bin_code % ( 10**digits ) )

def totp_code( secret, interval=30, digits=6, epoch_time=None ):
    """Gets the TOTP code"""
    import time

    if epoch_time is None:
        epoch_time = time.time()

    count = int(epoch_time / interval )
    return hotp_code( secret, count, digits )

def main():
    import fileinput
    import base64

    for line in fileinput.input():
        line = line.strip()
        try:
            secret = base64.b32decode(line.strip())
        except TypeError:
            print 'Unable to decode {} as a based 32 string.'.format(line)
            return -1

        print '{0:06d}'.format(totp_code(secret))

if __name__ == '__main__':
    main()

__author__ = "Gavin Hills"
