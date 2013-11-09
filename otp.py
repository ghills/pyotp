import base64
import time
import hashlib
import hmac
import struct

def LocalToNetworkByteArray( val ):
    ret = bytearray(8)
    ret[0] = 0
    ret[1] = 0
    ret[2] = 0
    ret[3] = 0
    ret[4] = ( val & 0xFF000000 ) >> 24
    ret[5] = ( val & 0x00FF0000 ) >> 16
    ret[6] = ( val & 0x0000FF00 ) >> 8
    ret[7] = ( val & 0x000000FF )
    return ret

def GetSHA1Digest( key, counter ):
    return bytearray(hmac.new( key=key, msg=counter, digestmod=hashlib.sha1 ).digest())

def GetBinCode( digest ):
    offset = digest[19] & 0xF
    bin_code = ( digest[offset] & 0x7F ) << 24 \
        | ( digest[offset+1] & 0xFF ) << 16    \
        | ( digest[offset+2] & 0xFF ) << 8     \
        | ( digest[offset+3] & 0xFF )
    return bin_code

def ScaleToNDigits( val, n ):
    return( val % ( 10**n ) )

def GetTimeCount( time_interval ):
    return int(time.time() / time_interval)

def GetCurrentTOTPCode(secret, interval=30 ):
    count = GetTimeCount( interval )
    count_hash = LocalToNetworkByteArray(count)
    digest = GetSHA1Digest(key=secret,counter=count_hash)
    bin_code = GetBinCode(digest)
    return ScaleToNDigits( bin_code, 6 )

def main():
    import fileinput

    for line in fileinput.input():
        line = line.strip().upper()
        try:
            secret = base64.b32decode(line.strip())
        except TypeError:
            print 'Unable to decode {} as a based 32 string.'.format(line)
            return -1
        print '{0:06d}'.format(GetCurrentTOTPCode(secret))

if __name__ == '__main__':
    main()

