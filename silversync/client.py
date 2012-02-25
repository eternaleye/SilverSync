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
import warnings
import sys
from M2Crypto.EVP import Cipher

class SyncException(Exception):
    pass

class InvalidPassphrase(SyncException):
    pass

class InvalidUser(SyncException):
    pass

class InvalidRequest(SyncException):
    pass

class ResourceNotFound(SyncException):
    pass

class NoSuchCollection(SyncException):
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
        if not self.check_username():
            raise InvalidUser()
        if self.passphrase is None:
            raise InvalidPassphrase()

        self.node = self.get_node().rstrip('/')
        self.encryption_key = self.hmac_sha256(self.passphrase, "%s%s\x01" % (self.HMAC_INPUT, self.username))
        self.get_key()

    def check_username(self):
        url = self.server + '/user/1.0/' + self.username
        r = requests.get(url)
        if int(r.text) == 0:
            return False
        else:
            return True

    def check_errors(self, r):
        if r.status_code == 400:
            raise InvalidRequest()
        elif r.status_code == 401:
            raise Unauthorized()
        elif r.status_code == 404:
            raise ResourceNotFound()
        elif r.status_code == 503:
            timeout = int(r.headers['X-Weave-Backoff'])
            return timeout
        if not r.ok:
            raise Unknown(r.text)

        return 0

    def get_node(self):
        url = self.server + '/user/1.0/' + self.username + '/node/weave'
        r = requests.get(url, auth=(self.username, self._password))
        timeout = self.check_errors(r)
        if timeout != 0:
            warnings.warn("Server under load; waiting for " + timeout + " as requested.")
            sleep(timeout)
            self.get_node()

        return r.text
        
    def get(self, path, **kwargs):
        url = self.url_from_path(path)
        r = requests.get(url, auth=(self.username, self._password), params=kwargs)
        timeout = self.check_errors(r)
        if timeout != 0:
            warnings.warn("Server under load; waiting for " + timeout + " as requested.")
            sleep(timeout)
            self.get(path, **kwargs)
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
            raise NoSuchCollection()
        self.sync = syncObj

    def getCollectionLocation(self):
        return "storage/" + self.handles

    def getEntryLocation(self, syncID):
        return self.getCollectionLocation() + "/" + syncID

    def getEntry(self, syncID):
        return self.sync.decrypt(
            json.loads(
                self.sync.get(
                    self.getEntryLocation(
                        syncID
                    )
                )['payload']
            )
        )

    def buildData(self, **kwargs):
        entries = self.sync.get(self.getCollectionLocation(), **kwargs )
        if kwargs.has_key('full'):
            return itertools.imap(
                self.sync.decrypt, itertools.imap(
                    json.loads, itertools.imap(
                        lambda entry: entry['payload'], entries
                    )
                )
            )
        else:
            return itertools.imap(self.getEntry, entries)

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
    class StorageVersionUnsupported(SyncException):
        pass

    sys.stderr.write("Username: ")
    username = raw_input()
    sys.stderr.write("Password: ")
    password = raw_input()
    sys.stderr.write("Sync key: ")
    passphrase = raw_input()

    try:
        from credentials import username, password, passphrase
    except ImportError:
        pass

    s = Sync(username, password, passphrase)
    meta = s.get_meta()
    if meta['storageVersion'] != 5:
        raise StorageVersionUnsupported()

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
        r[collection] = map( lambda x: x, engines[collection].buildData(full=1) if engines.has_key(collection) else GenericEngine(s, collection).buildData(full=1))

    print json.dumps( r )

if __name__ == '__main__':
    main()
