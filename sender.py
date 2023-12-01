from pyhpke import KEMId, KDFId, AEADId, CipherSuite
import json
import shared_variables as sv

suite: CipherSuite = CipherSuite.new(KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM)

# BASE TEST
base_keypair_s = suite.kem.derive_key_pair(sv.ikm_base_s)
base_keypair_r = suite.kem.derive_key_pair(sv.ikm_base_r)
base_enc, base_sender = suite.create_sender_context(base_keypair_r.public_key, sv.info_base)
base_ct = base_sender.seal(sv.plaintext, sv.aad_base)

# PSK TEST
psk_keypair_s = suite.kem.derive_key_pair(sv.ikm_psk_s)
psk_keypair_r = suite.kem.derive_key_pair(sv.ikm_psk_r)
psk_enc, psk_sender = suite.create_sender_context(psk_keypair_r.public_key, sv.info_psk, psk=sv.psk_psk, psk_id=sv.psk_id_psk)
psk_ct = psk_sender.seal(sv.plaintext, sv.aad_psk)

# AUTH TEST
auth_keypair_s = suite.kem.derive_key_pair(sv.ikm_auth_s)
auth_keypair_r = suite.kem.derive_key_pair(sv.ikm_auth_r)
auth_enc, auth_sender = suite.create_sender_context(auth_keypair_r.public_key, sv.info_auth, auth_keypair_s.private_key)
auth_ct = auth_sender.seal(sv.plaintext, sv.aad_auth)

# AUTH PSK TEST
auth_psk_keypair_s = suite.kem.derive_key_pair(sv.ikm_auth_psk_s)
auth_psk_keypair_r = suite.kem.derive_key_pair(sv.ikm_auth_psk_r)
auth_psk_enc, auth_psk_sender = suite.create_sender_context(
    auth_psk_keypair_r.public_key, sv.info_auth_psk, auth_psk_keypair_s.private_key, sv.psk_auth_psk, sv.psk_id_auth_psk)
auth_psk_ct = auth_psk_sender.seal(sv.plaintext, sv.aad_auth_psk)

# create 4 jsons with the different data depending on the mode
json_base = {
    'mode': 0,
    'kem_id': KEMId.DHKEM_P256_HKDF_SHA256.value,
    'kdf_id': KDFId.HKDF_SHA256.value,
    'aead_id': AEADId.AES128_GCM.value,
    'info': sv.info_base.hex(),
    'pk_s': base_keypair_s.public_key.to_public_bytes().hex(),
    'pk_r': base_keypair_r.public_key.to_public_bytes().hex(),
    'enc': base_enc.hex(),
    'encryption': {
        'ct': base_ct.hex(),
        'aad': sv.aad_base.hex()
    }
}

json_psk = {
    'mode': 1,
    'kem_id': KEMId.DHKEM_P256_HKDF_SHA256.value,
    'kdf_id': KDFId.HKDF_SHA256.value,
    'aead_id': AEADId.AES128_GCM.value,
    'info': sv.info_psk.hex(),
    'psk': sv.psk_psk.hex(),
    'psk_id': sv.psk_id_psk.hex(),
    'pk_s': psk_keypair_s.public_key.to_public_bytes().hex(),
    'pk_r': psk_keypair_r.public_key.to_public_bytes().hex(),
    'enc': psk_enc.hex(),
    'encryption': {
        'ct': psk_ct.hex(),
        'aad': sv.aad_psk.hex()
    }
}

json_auth = {
    'mode': 2,
    'kem_id': KEMId.DHKEM_P256_HKDF_SHA256.value,
    'kdf_id': KDFId.HKDF_SHA256.value,
    'aead_id': AEADId.AES128_GCM.value,
    'info': sv.info_auth.hex(),
    'pk_s': auth_keypair_s.public_key.to_public_bytes().hex(),
    'pk_r': auth_keypair_r.public_key.to_public_bytes().hex(),
    'enc': auth_enc.hex(),
    'encryption': {
        'ct': auth_ct.hex(),
        'aad': sv.aad_auth.hex()
    }
}

json_auth_psk = {
    'mode': 3,
    'kem_id': KEMId.DHKEM_P256_HKDF_SHA256.value,
    'kdf_id': KDFId.HKDF_SHA256.value,
    'aead_id': AEADId.AES128_GCM.value,
    'info': sv.info_auth_psk.hex(),
    'psk': sv.psk_auth_psk.hex(),
    'psk_id': sv.psk_id_auth_psk.hex(),
    'pk_s': auth_psk_keypair_s.public_key.to_public_bytes().hex(),
    'pk_r': auth_psk_keypair_r.public_key.to_public_bytes().hex(),
    'enc': auth_psk_enc.hex(),
    'encryption': {
        'ct': auth_psk_ct.hex(),
        'aad': sv.aad_auth_psk.hex()
    }
}

# create the actual files
with open('vectors/base.json', 'w+') as f:
    json.dump(json_base, f)

with open('vectors/psk.json', 'w+') as f:
    json.dump(json_psk, f)

with open('vectors/auth.json', 'w+') as f:
    json.dump(json_auth, f)

with open('vectors/auth_psk.json', 'w+') as f:
    json.dump(json_auth_psk, f)
