import hashlib
import hmac

import pbkdf2


def passphrase_to_psk(passphrase, ssid):
    assert type(passphrase) == bytes, "Passphrase must be bytes"
    assert type(ssid) == bytes, "SSID must be bytes"

    vgl = pbkdf2.PBKDF2(passphrase, ssid, 4096).read(32)
    main = hashlib.pbkdf2_hmac("sha1", passphrase, ssid, 4096, 32)
    assert vgl == main, "PBKDF2-HMAC-SHA1 does not match PBKDF2"
    return main


def psk_to_pmk(psk, ssid):
    assert type(psk) == bytes, "PSK must be bytes"
    assert type(ssid) == bytes, "SSID must be bytes"

    return hashlib.pbkdf2_hmac("sha1", psk, ssid, 4096, 32)


def custom_prf512(pmk, a_nonce, s_nonce, a_mac, s_mac):
    assert type(pmk) == bytes, "PMK must be bytes"
    assert type(a_nonce) == bytes, "A nonce must be bytes"
    assert type(s_nonce) == bytes, "S nonce must be bytes"
    assert type(a_mac) == bytes, "A MAC must be bytes"
    assert type(s_mac) == bytes, "S MAC must be bytes"

    a = b"Pairwise key expansion"
    key_data = min(a_nonce, s_nonce) + max(a_nonce, s_nonce) + min(a_mac, s_mac) + max(a_mac, s_mac)

    byte_length = 64
    i = 0
    ret = b''
    while i <= ((byte_length * 8 + 159) / 160):
        hmac_sha1 = hmac.new(pmk, a + bytes(0x00) + key_data + bytes(i), hashlib.sha1)
        i += 1
        ret = ret + hmac_sha1.digest()
    return ret[:byte_length]
