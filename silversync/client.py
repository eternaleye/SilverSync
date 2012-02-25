## Demonstrates certain parts of accessing (and decoding/decrypting)
## data stored by Firefox Sync ("Weave") from Python
##
##
## (c) 2011 Ivo van der Wijk, m3r consultancy. See LICENSE for licensing 
## details
##
## Based on https://github.com/iivvoo/Firefox-sync-example/blob/master/client.py
import requests ## easy_install this
import json
import base64
import hashlib
import hmac
import itertools
import pprint
from M2Crypto.EVP import Cipher

class SyncException(Exception):
    pass

class InvalidPassphrase(SyncException):
    pass

class Unauthorized(SyncException):
    pass

class Unknown(SyncException):
    pass

class Sync(object):
    server = "https://auth.services.mozilla.com"
    api = "1.0"
    HMAC_INPUT = "Sync-AES_256_CBC-HMAC256"

    def __init__(self, username, password, passphrase):
        self.username = username
        self._password =  password
        self.passphrase = self.decode_passphrase(passphrase)
        if self.passphrase is None:
            raise InvalidPassphrase()

        self.node = self.get_node().rstrip('/')
        self.encryption_key = self.hmac_sha256(self.passphrase, "%s%s\x01" % (self.HMAC_INPUT, self.username))
        self.get_key()

    def get_node(self):
        url = self.server + '/user/1.0/' + self.username + '/node/weave'
        r = requests.get(url, auth=(self.username, self._password))
        if r.status_code == 401:
            raise Unauthorized()
        if not r.ok:
            raise Unknown()

        return r.text
        
    def get(self, path):
        url = '/'.join((self.node, self.api, self.username, path))
        r = requests.get(url, auth=(self.username, self._password))
        return json.loads(r.text)

    def get_meta(self):
        data = self.get('storage/meta/global')
        payload = json.loads(data['payload'])
        return payload

    def cipher_decrypt(self, ciphertext, key, IV):
        cipher = Cipher(alg='aes_256_cbc', key=key, iv=IV, op=0)
        v = cipher.update(ciphertext)
        v = v + cipher.final()
        del cipher
        return json.loads(v)

    def get_key(self):
        data = self.get("storage/crypto/keys")
        payload = json.loads(data['payload'])
        ciphertext = payload['ciphertext'].decode("base64")
        IV = payload['IV'].decode("base64")
        hmac = payload['hmac'].decode("base64")
        
        default = self.cipher_decrypt(ciphertext, self.encryption_key, IV)['default']
        self.privkey = default[0].decode("base64")
        self.privhmac = default[1].decode("base64")

    def decrypt(self, data):
        ciphertext = data['ciphertext'].decode("base64")
        IV = data['IV'].decode("base64")
        hmac = data['hmac'].decode("base64")

        return self.cipher_decrypt(ciphertext, self.privkey, IV)

    @staticmethod
    def hmac_sha256(key, s):
        return hmac.new(key, s, hashlib.sha256).digest()

    @staticmethod
    def decode_passphrase(p):
        def denormalize(k):
            """ transform x-xxxxx-xxxxx etc into something b32-decodable """
            tmp = k.replace('-', '').replace('8', 'l').replace('9', 'o').upper()
            padding = (8-len(tmp) % 8) % 8
            return tmp + '=' * padding
        try:
            return base64.b32decode(denormalize(p))
        except TypeError:
            return None

class Engine(object):
    handles = None
    sync = None

    def __init__(self, syncObj):
        if not syncObj.get_meta()['engines'].has_key(self.handles):
            raise SyncException()
        self.sync = syncObj

    def getCollectionLocation(self):
        return "storage/" + self.handles

    def getEntryLocation(self, syncID):
        return self.getCollectionLocation() + "/" + syncID

    def buildData(self):
        ids = self.sync.get(self.getCollectionLocation())
        return itertools.imap(
            self.sync.decrypt, itertools.imap(
                json.loads, itertools.imap(
                    self.sync.get, itertools.imap(
                        self.getCollectionLocation, ids
                    )
                )
            )
        )

    def buildDataFull(self):
        entries = self.sync.get(self.getCollectionLocation() + "?full=1")
        return itertools.imap(
            self.sync.decrypt, itertools.imap(
                json.loads, itertools.imap(
                    lambda entry: entry['payload'], entries
                )
            )
        )

class BookmarksEngine(Engine):
    handles = 'bookmarks'

class PasswordsEngine(Engine):
    handles = 'passwords'

class TabsEngine(Engine):
    handles = 'tabs'

class HistoryEngine(Engine):
    handles = 'history'

class ClientsEngine(Engine):
    handles = 'clients'

class FormsEngine(Engine):
    handles = 'forms'

class PrefsEngine(Engine):
    handles = 'prefs'

class GenericEngine(Engine):
    def __init__(self, syncObj, toHandle):
        self.handles = toHandle
        Engine.__init__(self, syncObj)

def main():
    username = raw_input("Username: ")
    password = raw_input("Password: ")
    passphrase = raw_input("Sync key: ")

    try:
        from credentials import username, password, passphrase
    except ImportError:
        pass

    s = Sync(username, password, passphrase)
    meta = s.get_meta()
    assert meta['storageVersion'] == 5

    r = {}
    r['meta'] = meta

    engines = dict(
        map(
            lambda engine: (engine.handles, engine), map(
                lambda engine: engine(s), [
                    BookmarksEngine, PasswordsEngine, TabsEngine, HistoryEngine, ClientsEngine, FormsEngine, PrefsEngine
                ]
            )
        )
    )

    for collection in r['meta']['engines'].keys():
        r[collection] = map( lambda x: x, engines[collection].buildDataFull() if engines.has_key(collection) else GenericEngine(s, collection).buildDataFull())

    print pprint.pprint( r )

if __name__ == '__main__':
    main()
