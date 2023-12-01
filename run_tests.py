import json
import os
from pyhpke import CipherSuite, KEMId, KDFId, AEADId

# load json with official test vectors
with open('vectors/test-vectors.json', 'r') as f:
    test_vectors = json.load(f)

for i, vector in enumerate(test_vectors):

    if not os.path.exists('vectors/test-results'):
        os.makedirs('vectors/test-results')
    with open(f'vectors/test-results/vector_{i}.txt', 'w+') as v:

        # set up the correct algorithms for KEM, KDF, AEAD based on the provided IDs
        suite: CipherSuite = CipherSuite.new(KEMId(vector['kem_id']), KDFId(vector['kdf_id']), AEADId(vector['aead_id']))

        # TEST ONLY VARIABLES:
        # shared_secret, key_schedule_context, secret, key, base_nonce, exporter_secret, pt, skRm, skEm, skSm
        # handle base case first (mode = 0)
        # base variables:
        # info, ikmR, ikmE, skRm, skEm, pkRm, pkEm, enc,
        info = bytes.fromhex(vector['info'])
        enc_v = bytes.fromhex(vector['enc'])
        # derive recipient keys and verify them
        recipient_keys = suite.kem.derive_key_pair(bytes.fromhex(vector['ikmR']))
        pub_key_R = suite.kem.deserialize_public_key(bytes.fromhex(vector['pkRm']))
        sec_key_R = suite.kem.deserialize_private_key(bytes.fromhex(vector['skRm']))
        if (recipient_keys.public_key.to_public_bytes() != pub_key_R.to_public_bytes()
                or recipient_keys.private_key.to_private_bytes() != sec_key_R.to_private_bytes()):
            raise RuntimeError('Recipient keys don\'t match.')
        # derive ephemeral keys and verify them
        ephemeral_keys = suite.kem.derive_key_pair(bytes.fromhex(vector['ikmE']))
        pub_key_E = suite.kem.deserialize_public_key(bytes.fromhex(vector['pkEm']))
        sec_key_E = suite.kem.deserialize_private_key(bytes.fromhex(vector['skEm']))
        if (ephemeral_keys.public_key.to_public_bytes() != pub_key_E.to_public_bytes()
                or ephemeral_keys.private_key.to_private_bytes() != sec_key_E.to_private_bytes()):
            raise RuntimeError('Ephemeral keys don\'t match.')
        # psk variables:
        # psk, psk_id
        psk = b''
        psk_id = b''
        # auth variables:
        # ikmS, skSm, pkSm
        sec_key_S = None
        pub_key_S = None
        mode_str = 'Base'
        if vector['mode'] == 1:  # PSK
            psk = bytes.fromhex(vector['psk'])
            psk_id = bytes.fromhex(vector['psk_id'])
            mode_str = 'PSK'
        elif vector['mode'] == 2:  # Auth
            # derive sender keys and verify them
            sender_keys = suite.kem.derive_key_pair(bytes.fromhex(vector['ikmS']))
            sec_key_S = suite.kem.deserialize_private_key(bytes.fromhex(vector['skSm']))
            pub_key_S = suite.kem.deserialize_public_key(bytes.fromhex(vector['pkSm']))
            if (sender_keys.public_key.to_public_bytes() != pub_key_S.to_public_bytes()
                    or sender_keys.private_key.to_private_bytes() != sec_key_S.to_private_bytes()):
                raise RuntimeError('Sender keys don\'t match.')
            mode_str = 'Auth'
        elif vector['mode'] == 3:  # AuthPSK
            psk = bytes.fromhex(vector['psk'])
            psk_id = bytes.fromhex(vector['psk_id'])
            # derive sender keys and verify them
            sender_keys = suite.kem.derive_key_pair(bytes.fromhex(vector['ikmS']))
            sec_key_S = suite.kem.deserialize_private_key(bytes.fromhex(vector['skSm']))
            pub_key_S = suite.kem.deserialize_public_key(bytes.fromhex(vector['pkSm']))
            if (sender_keys.public_key.to_public_bytes() != pub_key_S.to_public_bytes()
                    or sender_keys.private_key.to_private_bytes() != sec_key_S.to_private_bytes()):
                raise RuntimeError('Sender keys don\'t match.')
            mode_str = 'AuthPSK'
        elif vector['mode'] != 0:
            raise RuntimeError('Mode not recognized.')

        # set up sender context to verify that enc matches as well
        enc, sender = suite.create_sender_context(pub_key_R, info, sec_key_S, psk, psk_id, ephemeral_keys)
        if enc != enc_v:
            raise RuntimeError('enc doesn\'t match')
        v.write(mode_str + ' mode.\n')
        # set up recipient context
        recipient = suite.create_recipient_context(enc_v, sec_key_R, info, pub_key_S, psk, psk_id)

        # handle export only AEAD
        if vector['aead_id'] == 0xFFFF:
            v.write('\tEXPORT ONLY AEAD\n')
            for j, data in enumerate(vector['exports']):
                ec = bytes.fromhex(data['exporter_context'])  # exporter context
                eL = data['L']  # length
                if recipient.export(ec, eL) == bytes.fromhex(data['exported_value']):  # TEST ONLY exported value
                    v.write('\t\tExport n.%i: Match!\n' % j)
                else:
                    raise RuntimeError('Exported data doesn\'t match')
        else:  # otherwise assume it's encrypted data
            for j, data in enumerate(vector['encryptions']):
                pt = bytes.fromhex(data['pt'])  # TEST ONLY plaintext for verification
                aad = bytes.fromhex(data['aad'])  # additional data
                ct = bytes.fromhex(data['ct'])  # ciphertext
                if (d := recipient.open(ct, aad)) == pt:
                    v.write('\tCiphertext n.%i: Match!\n' % j)
                    v.write(f'\t\tplaintext={pt}\n')
                    v.write(f'\t\tdecrypted={d}\n')
                else:
                    raise RuntimeError('Encrypted data doesn\'t match')
