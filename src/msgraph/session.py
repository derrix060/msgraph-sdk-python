
import zlib
import base64
import pickle
from time import time
import keyring
from .session_base import SessionBase


def get_keyring_key(account_id):
    return Session.KEYRING_ACCOUNT_KEY_PREFIX + account_id


class Session(SessionBase):

    SESSION_ARG_KEYNAME = 'key'
    KEYRING_SERVICE_NAME = 'msgraph_python_sdk'
    KEYRING_ACCOUNT_KEY_PREFIX = 'user.'
    PICKLE_PROTOCOL = 3

    def __init__(self,
                 token_type,
                 expires_in,
                 scope_string,
                 access_token,
                 client_id,
                 auth_server_url,
                 redirect_uri,
                 refresh_token=None,
                 client_secret=None):
        self.token_type = token_type
        self._expires_at = time() + int(expires_in)
        self.scope = scope_string.split(" ")
        self.access_token = access_token
        self.client_id = client_id
        self.auth_server_url = auth_server_url
        self.redirect_uri = redirect_uri
        self.refresh_token = refresh_token
        self.client_secret = client_secret

    @property
    def expires_in_sec(self):
        return self._expires_at - time()

    def is_expired(self):
        """Whether or not the session has expired
        Returns:
            bool: True if the session has expired, otherwise false
        """
        # Add a 10 second buffer in case the token is just about to expire
        return self._expires_at < time() - 10

    def refresh_session(self, expires_in, scope_string, access_token, refresh_token):
        self._expires_at = time() + int(expires_in)
        self.scope = scope_string.split(" ")
        self.access_token = access_token
        self.refresh_token = refresh_token

    def save_session(self, **save_session_kwargs):
        """Save the current session.
        
        Args:
            save_session_kwargs (dicr): To be used by implementation
            of save_session, however save_session wants to use them.
        """
        if self.SESSION_ARG_KEYNAME not in save_session_kwargs:
            raise ValueError('"%s" must be specified in save_session() argument.' % self.SESSION_ARG_KEYNAME)
        data = base64.b64encode(zlib.compress(pickle.dumps(self, self.PICKLE_PROTOCOL))).decode('utf-8')
        keyring.set_password(self.KEYRING_SERVICE_NAME, save_session_kwargs[self.SESSION_ARG_KEYNAME], data)

    @staticmethod
    def load_session(**load_session_kwargs):
        """Load the current session.
        
        Args:
            load_session_kwargs (dict): To be used by implementation
            of load_session, however load_session wants to use them. 
        Returns:
            :class:`Session`: The loaded session
        """
        keyarg = Session.SESSION_ARG_KEYNAME
        if keyarg not in load_session_kwargs:
            raise ValueError('"%s" must be specified in load_session() argument.' % keyarg)
        saved_data = keyring.get_password(Session.KEYRING_SERVICE_NAME, load_session_kwargs[keyarg])
        
        if saved_data is None:
            raise ValueError("Don't find anything")
        
        data = zlib.decompress(base64.b64decode(saved_data.encode('utf-8')))
        return pickle.loads(data)