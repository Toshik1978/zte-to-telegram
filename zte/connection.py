import base64
import hashlib
import secrets
import urllib.parse
from logging import Logger

import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from jsonpath_ng.ext import parse

from zte.exception import ZteModemException

# Documentation: https://wijayamin.github.io/zte-modem-api-docs/

ZTE_API_BASE = "/goform/"
GET_CMD = "goform_get_cmd_process"
SET_CMD = "goform_set_cmd_process"
REQUEST_TIMEOUT = 30

PEM_HEADER = "-----BEGIN PUBLIC KEY-----"
PEM_FOOTER = "-----END PUBLIC KEY-----"


def _normalize_pem(pem: str) -> str:
    """The device returns its public key PEM without the line breaks RSA.import_key expects."""
    body = pem.removeprefix(PEM_HEADER).removesuffix(PEM_FOOTER).strip()
    return f"{PEM_HEADER}\n{body}\n{PEM_FOOTER}"


def _decrypt_zte_field(encrypted_text: str, session_key: bytes | None) -> str:
    """Decrypt an SMS ``number``/``content`` field.

    Newer ZTE firmware encrypts these fields with AES-256-GCM using a session key
    negotiated over RSA at login (see ``ZteConnection.login``). Older firmware sends
    them as plain hexadecimal, which is returned unchanged.
    """
    if not encrypted_text or session_key is None:
        return encrypted_text
    if all(c in "0123456789abcdefABCDEF" for c in encrypted_text):
        return encrypted_text

    raw = base64.b64decode(encrypted_text)
    if len(raw) < 28:
        return encrypted_text
    iv, tag, ciphertext = raw[:12], raw[12:28], raw[28:]
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")


class ZteConnection:
    """Manages a session with a ZTE MC888 device."""

    __logger: Logger
    __url: str
    __password: str
    __cr_version: str
    __wa_inner_version: str
    __cookie: str
    __session_key: bytes | None

    def __init__(self, logger: Logger, host: str, password: str):
        self.__logger = logger
        self.__url = "http://" + host + "/"
        self.__password = password
        self.__session_key = None
        self.__cr_version = ""
        self.__wa_inner_version = ""

    def login(self) -> None:
        """Login to the ZTE MC888 device."""

        self.__parse_device_version()
        self.__cookie = self.__login(self._calculate_password(self.__get_ld()))
        self.__logger.debug("login: cookie: %s", str(self.__cookie))

        try:
            self.__session_key = self.__establish_encryption_session()
        except Exception:
            # Older firmware doesn't support this handshake and sends SMS fields as
            # plain hex; keep __session_key unset so _decrypt_zte_field leaves them as-is.
            self.__logger.debug(
                "Unable to establish an SMS encryption session; assuming firmware that sends unencrypted SMS fields",
                exc_info=True,
            )

    def logout(self) -> None:
        """Logout from the ZTE MC888 device."""

        self.__logout(self.__calculate_ad(self.__get_rd()))

    def get_all_sms(self, unread: bool) -> list:
        """Get the list of all SMS."""

        if unread:
            query = parse("$.messages[?(@.tag == '1' & @.received_all_concat_sms == '1')]")
        else:
            query = parse("$.messages[?(@.received_all_concat_sms == '1')]")

        r = self.__get_sms_list(0, 500)
        r.raise_for_status()

        # Extract matched values directly from JSONPath expression match objects
        results = [match.value for match in query.find(r.json())]
        self.__decrypt_messages(results)

        return results

    def read_all_sms(self, delete: bool) -> list:
        """Read all new SMS, then mark them read or delete them."""

        query = parse("$.messages[?(@.tag == '1' & @.received_all_concat_sms == '1')]")

        r = self.__get_sms_list(0, 500)
        r.raise_for_status()

        # Extract matched values directly from JSONPath expression match objects
        matches = [match.value for match in query.find(r.json())]
        if len(matches) == 0:
            return matches

        self.__decrypt_messages(matches)

        ids = [message["id"] for message in matches]
        self.__logger.debug("read_all_sms: ids: %s", ";".join(ids))

        ad = self.__calculate_ad(self.__get_rd())
        if delete:
            r = self.__delete_sms(ids, ad)
        else:
            r = self.__set_sms_read(ids, ad)
        if r is not None:
            if (result := r.json().get("result", "None")) != "success":
                raise ZteModemException("Non-successful read SMS result: ", result)

        return matches

    def __parse_device_version(self) -> None:
        headers = {"Referer": self.__url}
        params = {"isTest": "false", "cmd": "Language%2Ccr_version%2Cwa_inner_version", "multi_data": "1"}

        r = requests.get(self.__url + ZTE_API_BASE + GET_CMD, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        self.__logger.debug("login: getDeviceVersion response: %s", str(r.content))

        j = r.json()
        if (cr_version := j.get("cr_version", None)) is not None:
            self.__cr_version = cr_version
        if (wa_inner_version := j.get("wa_inner_version", None)) is not None:
            self.__wa_inner_version = wa_inner_version

    def __decrypt_messages(self, messages: list) -> None:
        for message in messages:
            for field in ("content", "number"):
                if field not in message:
                    continue
                try:
                    message[field] = _decrypt_zte_field(message[field], self.__session_key)
                except Exception:
                    self.__logger.warning("Unable to decrypt SMS id=%s field=%s", message.get("id"), field)

    def __establish_encryption_session(self) -> bytes:
        """Negotiate the AES-256-GCM session key the device uses to encrypt SMS fields.

        A random key is generated here, RSA-encrypted with the device's public key, and
        handed to the device via ``web_http_enstr_set`` so it can encrypt subsequent
        SMS ``number``/``content`` fields with it.
        """

        headers = {"Referer": self.__url}
        cookies = {"stok": self.__cookie}
        params = {"isTest": "false", "cmd": "web_crt_get"}

        r = requests.get(
            self.__url + ZTE_API_BASE + GET_CMD,
            params=params,
            headers=headers,
            cookies=cookies,
            timeout=REQUEST_TIMEOUT,
        )
        r.raise_for_status()
        pem = r.json().get("result")
        if not pem:
            raise ZteModemException("Unable to get device public key: ", str(r.content))

        public_key = RSA.import_key(_normalize_pem(pem))
        session_key = secrets.token_bytes(32)
        encrypted_key = PKCS1_v1_5.new(public_key).encrypt(session_key.hex().encode("utf-8"))
        web_enstr = base64.b64encode(encrypted_key).decode("ascii")

        headers = {"Origin": self.__url, "Referer": self.__url}
        params = {
            "isTest": "false",
            "goformId": "web_http_enstr_set",
            "web_enstr": web_enstr,
            "AD": self.__calculate_ad(self.__get_rd()),
        }

        r = requests.post(
            self.__url + ZTE_API_BASE + SET_CMD,
            data=params,
            headers=headers,
            cookies=cookies,
            timeout=REQUEST_TIMEOUT,
        )
        r.raise_for_status()
        if r.json().get("result") != "success":
            raise ZteModemException("Unable to establish encryption session: ", str(r.content))

        return session_key

    def __get_ld(self) -> str:
        headers = {"Referer": self.__url}
        params = {"isTest": "false", "cmd": "LD"}

        r = requests.get(self.__url + ZTE_API_BASE + GET_CMD, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        ld = r.json().get("LD", None)
        if ld is None:
            raise ZteModemException("Unable to get LD: ", str(r.content))
        self.__logger.debug("LD: %s", ld)
        return ld

    def __get_rd(self) -> str:
        headers = {"Referer": self.__url}
        params = {"isTest": "false", "cmd": "RD"}

        r = requests.get(self.__url + ZTE_API_BASE + GET_CMD, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        rd = r.json().get("RD", None)
        if rd is None:
            raise ZteModemException("Unable to get RD: ", str(r.content))
        self.__logger.debug("RD: %s", rd)
        return rd

    def _calculate_password(self, ld: str) -> str:
        """Calculate the login password hash."""

        prefix_hash = hashlib.sha256(self.__password.encode("utf-8")).hexdigest().upper()
        return hashlib.sha256((prefix_hash + ld.upper()).encode("utf-8")).hexdigest().upper()

    def __calculate_ad(self, rd: str) -> str:
        prefix_hash = hashlib.sha256((self.__wa_inner_version + self.__cr_version).encode("utf-8")).hexdigest().upper()
        return hashlib.sha256((prefix_hash + rd.upper()).encode("utf-8")).hexdigest().upper()

    def __login(self, password: str) -> str:
        headers = {"Origin": self.__url, "Referer": self.__url}
        params = {"isTest": "false", "goformId": "LOGIN", "password": password}

        r = requests.post(self.__url + ZTE_API_BASE + SET_CMD, data=params, headers=headers, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        result = r.json().get("result", "-1")
        if result != "0":
            raise ZteModemException("Non-successful login result: ", result)

        cookie = r.cookies.get("stok")
        if cookie is None:
            raise ZteModemException("Unable to get auth cookie")
        return cookie

    def __logout(self, ad: str) -> None:
        headers = {"Origin": self.__url, "Referer": self.__url}
        cookies = {"stok": self.__cookie}
        params = {"isTest": "false", "goformId": "LOGOUT", "AD": ad}

        r = requests.post(
            self.__url + ZTE_API_BASE + SET_CMD, data=params, headers=headers, cookies=cookies, timeout=REQUEST_TIMEOUT
        )
        r.raise_for_status()
        result = r.json().get("result", "None")
        if result != "success":
            raise ZteModemException("Non-successful logout result: ", result)

    def __get_sms_list(self, page: int, num_entries: int) -> requests.Response:
        headers = {"Referer": self.__url}
        cookies = {"stok": self.__cookie}
        params = {
            "isTest": "false",
            "cmd": "sms_data_total",
            "page": page,
            "data_per_page": num_entries,
            "mem_store": "1",
            "tags": "10",
            "order_by": "order+by+id+desc",
        }
        params_safe = urllib.parse.urlencode(params, safe="+")

        return requests.get(
            self.__url + ZTE_API_BASE + GET_CMD,
            params=params_safe,
            headers=headers,
            cookies=cookies,
            timeout=REQUEST_TIMEOUT,
        )

    def __set_sms_read(self, ids: list, ad: str) -> requests.Response | None:
        if len(ids) == 0:
            return None

        msg_ids = "".join(str(msg_id) + ";" for msg_id in ids)

        headers = {"Origin": self.__url, "Referer": self.__url}
        cookies = {"stok": self.__cookie}
        params = {"isTest": "false", "goformId": "SET_MSG_READ", "msg_id": msg_ids, "tag": "0", "AD": ad}

        return requests.post(
            self.__url + ZTE_API_BASE + SET_CMD, data=params, headers=headers, cookies=cookies, timeout=REQUEST_TIMEOUT
        )

    def __delete_sms(self, ids: list, ad: str) -> requests.Response | None:
        if len(ids) == 0:
            return None

        msg_ids = "".join(str(msg_id) + ";" for msg_id in ids)

        headers = {"Origin": self.__url, "Referer": self.__url}
        cookies = {"stok": self.__cookie}
        params = {"isTest": "false", "goformId": "DELETE_SMS", "msg_id": msg_ids, "AD": ad}

        return requests.post(
            self.__url + ZTE_API_BASE + SET_CMD, data=params, headers=headers, cookies=cookies, timeout=REQUEST_TIMEOUT
        )
