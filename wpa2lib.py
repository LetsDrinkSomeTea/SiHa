import hashlib
import hmac


def psk_to_pmk(psk, ssid):
    assert type(psk) == bytes, "PSK must be bytes"
    assert type(ssid) == bytes, "SSID must be bytes"

    return hashlib.pbkdf2_hmac("sha1", psk, ssid, 4096, 32)


def make_ab(a_nonce, s_nonce, a_mac, s_mac):
    assert type(a_nonce) == bytes, "A nonce must be bytes"
    assert type(s_nonce) == bytes, "S nonce must be bytes"
    assert type(a_mac) == bytes, "A MAC must be bytes"
    assert type(s_mac) == bytes, "S MAC must be bytes"

    a = b"Pairwise key expansion"
    b = min(a_mac, s_mac) + max(a_mac, s_mac) \
        + min(a_nonce, s_nonce) + max(a_nonce, s_nonce)
    return a, b


def prf_384(key, a, b):
    assert type(key) == bytes, "Key must be bytes"
    assert type(a) == bytes, "A must be bytes"
    assert type(b) == bytes, "B must be bytes"

    length = 384
    i = 0
    ret = b""
    while i <= (length + 159) / 160:
        c = a + b"\x00" + b + i.to_bytes(1, "big")
        ret += hmac.new(key, c, hashlib.sha1).digest()
        i += 1
    return ret[:48]


def make_mic(ptk, body, wpa=False):
    assert type(ptk) == bytes, "PTK must be bytes"
    assert type(body) == bytes, "Data must be bytes"

    hmac_func = hashlib.md5 if wpa else hashlib.sha1
    mic = hmac.new(ptk[0:16], body, hmac_func).digest()[:16]
    return mic


def validate_mic(psk, ssid, a_nonce, s_nonce, a_mac, s_mac, body, mic):
    assert type(psk) == bytes, "PSK must be bytes"
    assert type(ssid) == bytes, "SSID must be bytes"
    assert type(a_nonce) == bytes, "A nonce must be bytes"
    assert type(s_nonce) == bytes, "S nonce must be bytes"
    assert type(a_mac) == bytes, "A MAC must be bytes"
    assert type(s_mac) == bytes, "S MAC must be bytes"
    assert type(body) == bytes, "Data must be bytes"
    assert type(mic) == bytes, "MIC must be bytes"

    pmk = psk_to_pmk(psk, ssid)
    ptk = prf_384(pmk, *make_ab(a_nonce, s_nonce, a_mac, s_mac))
    return make_mic(ptk, body) == mic


class WPA2Validator:
    def __init__(
            self, ssid, a_nonce, s_nonce,
            a_mac, s_mac, body, mic):
        self.ssid = ssid
        self.a_nonce = a_nonce
        self.s_nonce = s_nonce
        self.a_mac = a_mac
        self.s_mac = s_mac
        self.body = body
        self.mic = mic

    def validate(self, password):
        psk = password.encode("utf-8")
        return validate_mic(
            psk, self.ssid, self.a_nonce,
            self.s_nonce, self.a_mac, self.s_mac,
            self.body, self.mic)
