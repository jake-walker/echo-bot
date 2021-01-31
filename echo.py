"""Simple Echo client implementation."""
import secrets
import string
import hashlib
import socket
from enum import Enum
from typing import List
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import unpad, pad
from base64 import b64decode, b64encode
from logzero import logger
import time


def generate_key(key_size: int) -> str:
    """Create a random alphanumeric string of a given length.

    Args:
        key_size (int): The length of the string to generate.

    Returns:
        str: The generated alphanumeric string.
    """
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for i in range(key_size))


class CommandHandler:
    """Class for managing the registration of command functions."""
    commands = {}
    raw = []

    @classmethod
    def register_command(cls, *args):  # noqa
        def decorator(fn):  # noqa
            cls.commands[args[0]] = fn
            return fn
        return decorator

    @classmethod
    def register_raw(cls):  # noqa
        def decorator(fn):  # noqa
            cls.raw.append(fn)
            return fn
        return decorator


class EchoMessageType(Enum):
    """Echo message types."""
    disconnect = "disconnect"
    user_message = "userMessage"
    change_channel = "changeChannel"
    history = "historyRequest"
    server_info = "serverInfoRequest"
    client_secret = "clientSecret"
    connection_request = "connectionRequest"
    connection_accept = "CRAccepted"
    connection_denied = "CRDenied"
    server_info_res = "serverInfo"
    got_secret = "gotSecret"
    outbound_message = "outboundMessage"
    channel_update = "channelUpdate"


class EchoClient:
    """Echo client implementation."""
    # Are we currently connected to the server?
    connected = False

    host: str
    port: int
    user_id: str
    sock: socket.socket
    # Encryption key for sending messages after initial handshake
    session_key: bytes
    # Bot username
    username: str
    # Server password
    password: str

    # The server's MOTD
    motd: str = None
    # A list of the server's channels
    channels: List[str] = []

    def __init__(self, host: str, port: int, id: str = "default",
                 username: str = "user", password: str = "mypassword") -> None:
        """Create a new Echo client.

        Args:
            host (str): The hostname of the Echo server.
            port (int): The port of the Echo server.
            id (str, optional): The user ID to use for the connection.
                Defaults to "default".
            username (str, optional): The name of the bot. Defaults to "user".
            password (str, optional): The password for connecting to the
                server. Defaults to "mypassword".
        """
        # TODO: Remove this after testing
        id = generate_key(32)

        self.host = host
        self.port = port
        self.user_id = hashlib.sha256(id.encode("utf-8")).hexdigest()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.session_key = generate_key(16).encode("utf-8")
        self.username = "bot_{}".format(username)
        self.password = password

    def connect(self) -> None:
        """Connect to the Echo server and perform a handshake."""
        logger.info("Initiating connection to {}:{}".format(self.host,
                                                            self.port))
        self.sock.connect((self.host, self.port))

        # initiate connection handshake
        logger.debug("Sending server info request...")
        # server info request
        self.send(None, EchoMessageType.server_info, encrypt=False)
        # server info response
        server_info_response = self.receive(decrypt=False,
                                            expected_type=EchoMessageType.
                                            server_info_res)

        # session key request
        logger.debug("Sending session key...")
        server_key = RSA.import_key(server_info_response["data"])
        rsa = PKCS1_OAEP.new(server_key)
        response = b64encode(rsa.encrypt(self.session_key)).decode("utf-8")
        self.send(response, EchoMessageType.client_secret, encrypt=False)
        # session key response
        session_key_response = self.receive(decrypt=True,
                                            expected_type=EchoMessageType.
                                            got_secret)

        logger.debug("Sending connection request...")
        # connection request
        payload = json.dumps([self.username, self.password])
        self.send(payload, EchoMessageType.connection_request)
        # connection response
        connection_response = self.receive()

        if (connection_response["messagetype"] == EchoMessageType.
                connection_denied.value):
            logger.error("Connection denied: {}".format(
                connection_response["data"]))
            return

        # server data response
        server_data_response = self.receive()
        data_payload = json.loads(server_data_response["data"])
        self.channels = json.loads(data_payload[0])
        self.motd = data_payload[1]

        logger.info("Connection established! - {}".format(self.motd))

        self.connected = True

        logger.debug("Got channels: {}".format(self.channels))
        self.switch_channel(self.channels[0])

    def switch_channel(self, channel: str) -> None:
        """Switch to a given channel.

        Args:
            channel (str): The channel name to switch to.
        """
        logger.info("Switching channel to {}...".format(channel))
        assert channel in self.channels
        self.send(channel, EchoMessageType.change_channel)

    def disconnect(self) -> None:
        """Gracefully disconnect from the server."""
        self.send(None, EchoMessageType.disconnect)
        self.connected = False
        logger.info("Gracefully disconnected from server")

    def send(self, data: str,
             type: EchoMessageType = EchoMessageType.user_message,
             subtype: str = None, metadata: List[str] = None,
             encrypt: bool = True) -> None:
        """Send a message to the server.

        Args:
            data (str): The message to send to the server.
            type (EchoMessageType, optional): The type of message to send.
                Defaults to EchoMessageType.user_message.
            subtype (str, optional): The message subtype. Defaults to None.
            metadata (List[str], optional): Message metadata. Defaults to None.
            encrypt (bool, optional): Whether to encrypt the message.
                Defaults to True.
        """
        message = {
            "userid": self.user_id,
            "messagetype": type.value,
            "subtype": subtype,
            "data": "" if data is None else data,
            "metadata": json.dumps([] if metadata is None else metadata)
        }

        out = json.dumps(message).encode("utf-8")

        if encrypt:
            aes = AES.new(self.session_key, AES.MODE_CBC)
            cipher_text = b64encode(aes.encrypt(pad(out, AES.block_size))
                                    ).decode("utf-8")
            iv = b64encode(aes.iv).decode("utf-8")
            out = json.dumps([cipher_text, iv]).encode("utf-8")

        # chunks = list(out[0+i:1024+i] for i in range(0, len(out), 1024))
        # for chunk in chunks:
        #    self.sock.send(chunk)
        self.sock.send(out)

        # TODO: Remove this after server issue fixed
        if type == EchoMessageType.user_message:
            time.sleep(0.2)

    def receive(self, decrypt: bool = True,
                expected_type: EchoMessageType = None) -> dict:
        """Receive a message from the server.

        Args:
            decrypt (bool, optional): Whether to decrypt the message.
                Defaults to True.
            expected_type (EchoMessageType, optional): The message type that
                is being expected. Defaults to None.

        Raises:
            Exception: The received message type differs from what was being
                expected.

        Returns:
            dict: The received message.
        """
        received = json.loads(self.sock.recv(20480).decode("utf-8"))

        if not decrypt:
            return received

        data, iv = map(b64decode, received)
        aes = AES.new(self.session_key, AES.MODE_CBC, iv)
        plain_text = unpad(aes.decrypt(data), AES.block_size).decode("utf-8")
        message = json.loads(plain_text)

        if (expected_type is not None and message["messagetype"
                                                  ] != expected_type.value):
            raise Exception("Expected message type '{}' and got '{}'"
                            .format(expected_type.value,
                                    message["messagetype"]))

        return message

    def loop(self) -> None:
        """Handle incoming messages in a loop."""
        while self.connected:
            message = self.receive()

            # Skip processing if not an outbound message
            if (message["messagetype"] != EchoMessageType.outbound_message.
                    value):
                logger.debug("Ignoring {} message: {}"
                             .format(message["messagetype"], message["data"]))
                continue

            # Skip processing if the message was sent by us
            message_metadata = json.loads(message["metadata"])
            sender = message_metadata[0]
            content = message["data"]
            if sender.startswith("bot_"):
                continue

            logger.debug("New message from {}: {}".format(sender, content))

            if content.startswith("!"):
                parts = content[1:].split(" ")
                logger.debug("Handling command {}".format(parts[0]))
                if parts[0] in CommandHandler.commands:
                    try:
                        CommandHandler.commands[parts[0]](self, parts)
                    except Exception:
                        self.send("❌ There was a problem running that command")
                else:
                    self.send("{} is not a valid command!".format(parts[0]))
            else:
                logger.debug("Handling raw text {}".format(content))
                for handler in CommandHandler.raw:
                    handler(self, content)

# TODO: Handle disconnects and retrying connections
