from pyhpke import KEMId, KDFId, AEADId, CipherSuite
import json
import shared_variables as sv


def test_base_case():
    with open('vectors/base.json', 'r') as f:
        data = json.load(f)

    suite: CipherSuite = CipherSuite.new(KEMId(data['kem_id']), KDFId(data['kdf_id']), AEADId(data['aead_id']))

    info = bytes.fromhex(data['info'])
    enc = bytes.fromhex(data['enc'])
    skR = suite.kem.derive_key_pair(sv.ikm_base_r).private_key

    recipient = suite.create_recipient_context(enc, skR, info)
    ct = bytes.fromhex(data['encryption']['ct'])
    aad = bytes.fromhex(data['encryption']['aad'])
    pt = recipient.open(ct, aad)
    return pt


def test_psk_case():
    with open('vectors/psk.json', 'r') as f:
        data = json.load(f)

    suite: CipherSuite = CipherSuite.new(KEMId(data['kem_id']), KDFId(data['kdf_id']), AEADId(data['aead_id']))

    info = bytes.fromhex(data['info'])
    enc = bytes.fromhex(data['enc'])
    skR = suite.kem.derive_key_pair(sv.ikm_psk_r).private_key
    psk = bytes.fromhex(data['psk'])
    psk_id = bytes.fromhex(data['psk_id'])

    recipient = suite.create_recipient_context(enc, skR, info, psk=psk, psk_id=psk_id)
    ct = bytes.fromhex(data['encryption']['ct'])
    aad = bytes.fromhex(data['encryption']['aad'])
    pt = recipient.open(ct, aad)
    return pt


def test_auth_case():
    with open('vectors/auth.json', 'r') as f:
        data = json.load(f)

    suite: CipherSuite = CipherSuite.new(KEMId(data['kem_id']), KDFId(data['kdf_id']), AEADId(data['aead_id']))

    info = bytes.fromhex(data['info'])
    enc = bytes.fromhex(data['enc'])
    skR = suite.kem.derive_key_pair(sv.ikm_auth_r).private_key
    pkS = suite.kem.derive_key_pair(sv.ikm_auth_s).public_key

    recipient = suite.create_recipient_context(enc, skR, info, pkS)
    ct = bytes.fromhex(data['encryption']['ct'])
    aad = bytes.fromhex(data['encryption']['aad'])
    pt = recipient.open(ct, aad)
    return pt


def test_auth_psk_case():
    with open('vectors/auth_psk.json', 'r') as f:
        data = json.load(f)

    suite: CipherSuite = CipherSuite.new(KEMId(data['kem_id']), KDFId(data['kdf_id']), AEADId(data['aead_id']))

    info = bytes.fromhex(data['info'])
    enc = bytes.fromhex(data['enc'])
    skR = suite.kem.derive_key_pair(sv.ikm_auth_psk_r).private_key
    psk = bytes.fromhex(data['psk'])
    psk_id = bytes.fromhex(data['psk_id'])
    pkS = suite.kem.derive_key_pair(sv.ikm_auth_psk_s).public_key

    recipient = suite.create_recipient_context(enc, skR, info, pkS, psk, psk_id)
    ct = bytes.fromhex(data['encryption']['ct'])
    aad = bytes.fromhex(data['encryption']['aad'])
    pt = recipient.open(ct, aad)
    return pt


if __name__ == '__main__':
    print('       PLAINTEXT: ' + sv.plaintext.decode())
    print('     BASE output: ' + test_base_case().decode())
    print('     PSK  output: ' + test_psk_case().decode())
    print('     AUTH output: ' + test_auth_case().decode())
    print('AUTH_PSK  output: ' + test_auth_psk_case().decode())
