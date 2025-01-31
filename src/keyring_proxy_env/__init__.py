import dataclasses
import logging
import os

import keyring.backend
import keyring.credentials
import keyring.errors
from jaraco.classes import properties
from typing_extensions import Optional, Self

PRIORITY = 9.8

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class Credential:
    username: Optional[str]
    password: Optional[str]

    def to_keyring_cred(self) -> Optional[keyring.credentials.Credential]:
        if self.username is None:
            if self.password is None:
                return None
            return keyring.credentials.AnonymousCredential(self.password)
        return keyring.credentials.SimpleCredential(self.username, self.password or "")

    @classmethod
    def from_keyring_cred(cls, cred: keyring.credentials.Credential) -> Self:
        return cls(cred.username, cred.password)


def make_key(*args: Optional[str]) -> str:
    return "_".join(
        arg.upper().replace("-", "_").replace(".", "_").replace("/", "_").replace(" ", "_")
        for arg in args
        if arg is not None and arg != ""
    )


def get_key(key: str) -> Optional[str]:
    logger.debug(f"Getting {key!r}")
    return os.getenv(key)


class EnvProxyBackend(keyring.backend.KeyringBackend):
    logfile: str = "keyring-proxy.log"
    log: bool = False
    prefix: Optional[str] = "KP"
    username_suffix: Optional[str] = "USERNAME"
    password_suffix: Optional[str] = "PASSWORD"

    def __init__(self):
        super().__init__()
        if self.log:
            logging.basicConfig(level=logging.DEBUG)

    @properties.classproperty
    def priority(cls):
        return PRIORITY

    def _get_username(self, service: str):
        username_key = make_key(self.prefix, service, self.username_suffix)
        return get_key(username_key)

    def _get_password(self, service: str, username: Optional[str]):
        password_key = make_key(self.prefix, service, username, self.password_suffix)
        key = get_key(password_key)
        if key is None and username is not None:
            password_key = make_key(self.prefix, service, self.password_suffix)
            key = get_key(password_key)
        return key

    def _get_cred(self, service: str, username: Optional[str]):
        username = username if username is not None else self._get_username(service)
        password = self._get_password(service, username)
        return Credential(username, password)

    def get_credential(self, service: str, username: Optional[str]) -> Optional[keyring.credentials.Credential]:
        logger.debug(f"get_credential({service!r}, {username!r})")
        return self._get_cred(service, username).to_keyring_cred()

    def get_password(self, service: str, username: str) -> Optional[str]:
        logger.debug(f"get_password({service!r}, {username!r})")
        return self._get_password(service, username)

    def set_password(self, service: str, username: str, password: str):
        raise keyring.errors.PasswordSetError("set_password not implemented")

    def delete_password(self, service: str, username: str):
        raise keyring.errors.PasswordDeleteError("delete_password not implemented")
