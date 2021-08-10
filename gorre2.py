import zlib
import json  # Pretty printing
import cbor2  # `pip install cbor2`
from cose.messages import CoseMessage  # `pip install cose`
BASE45_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


cert = r'QR koodi stringinä tähän lol'


def b45decode(s):
    """Decode base45-encoded string to bytes"""
    res = []
    try:
        if isinstance(s, str):
            buf = [BASE45_CHARSET.index(c) for c in s]
        else:
            buf = [BASE45_CHARSET.index(c) for c in s.decode()]
        buflen = len(buf)
        for i in range(0, buflen, 3):
            x = buf[i] + buf[i + 1] * 45
            if buflen - i >= 3:
                x = buf[i] + buf[i + 1] * 45 + buf[i + 2] * 45 * 45
                res.extend(list(divmod(x, 256)))
            else:
                res.append(x)
        return bytes(res)
    except (ValueError, IndexError, AttributeError):
        raise ValueError("Invalid base45 string")


def main():
    print("Decoding base45")
    decoded_cert = b45decode(cert)
    print("Decompressing zlib")
    decomp_cert = zlib.decompress(decoded_cert)
    print("Getting CBOR from COSE payload")
    cose = CoseMessage.decode(decomp_cert)
    print("Decoding CBOR\n")
    print(json.dumps(cbor2.loads(cose.payload), indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
