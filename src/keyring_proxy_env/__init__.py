import dataclasses
import logging
import os

import keyring.backend
import keyring.credentials
import keyring.errors
from jaraco.classes import properties
from typing_extensions import Optional, Self

PRIORITY = 9.9

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class Credential:
    username: Optional[str]
    password: Optional[str]

    def to_keyring_cred(self) -> keyring.credentials.Credential:
        return keyring.credentials.SimpleCredential(self.username, self.password)

    @classmethod
    def from_keyring_cred(cls, cred: keyring.credentials.Credential) -> Self:
        return cls(cred.username, cred.password)


def make_key(*args: str) -> str:
    return "_".join(arg.upper().replace("-", "_").replace(".", "_") for arg in args)


def get_key(key: str) -> Optional[str]:
    logger.debug(f"Getting {key!r}")
    return os.getenv(key)


class EnvProxyBackend(keyring.backend.KeyringBackend):

    logfile: str = "keyring-proxy.log"
    log: bool = False
    prefix: str = "KEYRING"

    def __init__(self):
        super().__init__()
        if self.log:
            logging.basicConfig(level=logging.DEBUG)

    @properties.classproperty
    def priority(cls):
        return PRIORITY

    def _get_cred(self, service: str, username: Optional[str]):
        if username is None:
            username_key = make_key(self.prefix, service, "USERNAME")
            username = get_key(username_key)
        if username is not None:
            password_key = make_key(self.prefix, service, username, "PASSWORD")
            password = get_key(password_key)
            if password is None:
                password_key = make_key(self.prefix, service, "PASSWORD")
                password = get_key(password_key)
        else:
            password_key = make_key(self.prefix, service, "PASSWORD")
            password = get_key(password_key)

        if username is None and password is None:
            return None

        return Credential(username, password)

    def get_credential(self, service: str, username: Optional[str]) -> Optional[keyring.credentials.Credential]:
        logger.debug(f"get_credential({service!r}, {username!r})")
        result = self._get_cred(service, username)
        if result is None:
            return None
        return result.to_keyring_cred()

    def get_password(self, service: str, username: str) -> Optional[str]:
        logger.debug(f"get_password({service!r}, {username!r})")
        cred = self._get_cred(service, username)
        if cred is None:
            return None
        return cred.password

    def set_password(self, service: str, username: str, password: str):
        raise keyring.errors.PasswordSetError("set_password not implemented")

    def delete_password(self, service: str, username: str):
        raise keyring.errors.PasswordDeleteError("delete_password not implemented")
