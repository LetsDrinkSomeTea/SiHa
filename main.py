import wpa2


def hexdump_bytes(b):
    print("     " + " ".join("{:2x}".format(c) for c in range(16)))
    for i in range(0, len(b), 16):
        print("{:2x}x  ".format(int(i/16)) + " ".join("{:02x}".format(c) for c in b[i:i + 16]), end="")
        print("   " + "".join(chr(c) if 32 <= c <= 126 else "." for c in b[i:i + 16]))
    print("                                 {:3} bytes {:4} bits".format(len(b), len(b) * 8))


if __name__ == "__main__":
    password = "password"
    ssid = "ssid"
    a_nonce = "a_nonce"
    s_nonce = "s_nonce"
    a_mac = "a_mac"
    s_mac = "s_mac"

    password = password.encode("utf-8")
    ssid = ssid.encode("utf-8")
    a_nonce = a_nonce.encode("utf-8")
    s_nonce = s_nonce.encode("utf-8")
    a_mac = a_mac.encode("utf-8")
    s_mac = s_mac.encode("utf-8")

    psk = wpa2.passphrase_to_psk(password, ssid)
    pmk = wpa2.psk_to_pmk(psk, ssid)
    ptk = wpa2.custom_prf512(pmk, a_nonce, s_nonce, a_mac, s_mac)
    print("PSK:")
    hexdump_bytes(psk)
    print("PMK:")
    hexdump_bytes(pmk)
    print("PTK:")
    hexdump_bytes(ptk)

    kck = ptk[:16]
    kek = ptk[16:32]
    tk = ptk[32:48]
    print("KCK:")
    hexdump_bytes(kck)
    print("KEK:")
    hexdump_bytes(kek)
    print("TK:")
    hexdump_bytes(tk)