import libuser
import random
import hashlib

# Added by SSE_Group_2:
# Added the secrets module for generating secure tokens.
import secrets

from pathlib import Path

key_value = secrets.token_hex(16)
# using secrets to generate a random 16-character hex string
secret = key_value  # this used to be hardcoded as'MYSUPERSECRETKEY'
not_after = 60  # 1 minute


def keygen(username, password=None, login=True):
    if password:
        if not libuser.login(username, password):
            return None

    key = hashlib.sha256(str(random.getrandbits(2048)).encode()).hexdigest()

    for f in Path('/tmp/').glob('vulpy.apikey.' + username + '.*'):
        print('removing', f)
        f.unlink()

    keyfile = '/tmp/vulpy.apikey.{}.{}'.format(username, key)

    Path(keyfile).touch()

    return key


def authenticate(request):
    if 'X-APIKEY' not in request.headers:
        return None

    key = request.headers['X-APIKEY']

    for f in Path('/tmp/').glob('vulpy.apikey.*.' + key):
        return f.name.split('.')[2]

    return None
