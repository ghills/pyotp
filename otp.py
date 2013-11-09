import hashlib
import hmac
import struct

def int_to_big_endian_bytes( val ):
    # converts a value to a big endian ordered 8 byte array
    # used for hash input
    return bytearray( struct.pack('>Q',val) )

def sha1_digest( key, counter ):
    return bytearray(hmac.new( key=key, msg=counter, digestmod=hashlib.sha1 ).digest())

def dynamic_truncation( hmac_result ):
    # HMAC SHA-1 algorithm should output 20 bytes
    assert( len(hmac_result) == 20 )

    offset = hmac_result[19] & 0xF
    bin_code = ( hmac_result[offset] & 0x7F ) << 24     \
             | ( hmac_result[offset+1] & 0xFF ) << 16   \
             | ( hmac_result[offset+2] & 0xFF ) << 8    \
             | ( hmac_result[offset+3] & 0xFF )
    return bin_code

def hotp_code( secret, counter, digits=6 ):
    if digits < 6 or digits > 8:
        # the RFC only allows 6-8 digits
        raise Exception('Invalid number of digits: {}'.format(digits))

    count_hash = int_to_big_endian_bytes(counter)
    digest = sha1_digest(key=secret,counter=count_hash)
    bin_code = dynamic_truncation(digest)
    return ( bin_code % ( 10**digits ) )

def totp_code( secret, interval=30, digits=6 ):
    import time

    count = int(time.time() / interval )
    return hotp_code( secret, count, digits )

def main():
    import fileinput
    import base64
    for line in fileinput.input():
        line = line.strip().upper()
        try:
            secret = base64.b32decode(line.strip())
        except TypeError:
            print 'Unable to decode {} as a based 32 string.'.format(line)
            return -1
        print '{0:06d}'.format(totp_code(secret))

if __name__ == '__main__':
    main()

