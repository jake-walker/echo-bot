"""Launcher for Echo bot."""
from echo import EchoClient
from echo import CommandHandler
import re
import requests
from logzero import logger
import random
from typing import List


@CommandHandler.register_command("ping")
def cmd_ping(ctx: EchoClient, message_parts: List[str]) -> None:
    """Handle ping commands.

    Args:
        ctx (EchoClient): The EchoClient instance.
        message_parts (List[str]): The parts of the message.
    """
    if len(message_parts) > 1:
        ctx.send("🏓 Pong! You send me '{}'".format(
            " ".join(message_parts[1:])))
    else:
        ctx.send("🏓 Pong!")


@CommandHandler.register_command("dice")
def cmd_dice(ctx: EchoClient, message_parts: List[str]) -> None:
    """Handle dice roll commands.

    Args:
        ctx (EchoClient): The EchoClient instance.
        message_parts (List[str]): The parts of the message.
    """
    to = int(message_parts[1]) if len(message_parts) > 1 else 6
    ctx.send("🎲 You rolled {}!".format(random.randint(1, to)))


@CommandHandler.register_command("disconnect")
def cmd_disconnect(ctx: EchoClient, message_parts: List[str]) -> None:
    """Handle disconnect commands.

    Args:
        ctx (EchoClient): The EchoClient instance.
        message_parts (List[str]): The parts of the message.
    """
    # TODO: Stop regular users from running this
    ctx.send("👋 Goodbye!")
    ctx.disconnect()


@CommandHandler.register_raw()
def link_handler(ctx: EchoClient, message: str) -> None:
    """Search the message for links and send back the metadata for each link.

    Args:
        ctx (EchoClient): The EchoClient instance.
        message (str): The message.
    """
    link_regex = re.compile(('((https?):((//)|(\\\\))+([\w\d:#@%/;$()~_?\+-=\\'
                             '\.&](#!)?)*)'), re.DOTALL)
    links = [m[0] for m in re.findall(link_regex, message)]

    for link in links:
        r = requests.get(("http://url-metadata.herokuapp.com/api/metadata?"
                          "url={}&timeout=1000").format(link))
        if r.status_code != 200:
            logger.error("HTTP error while collecting URL metadata for {}: {}"
                         .format(link, r.status_code))
            continue

        response = r.json()
        if "error" in response:
            logger.error("Application error while collecting URL metadata "
                         "for {}: {}".format(link, response))
            continue

        metadata = response.get("data", {})

        ctx.send("[{}] {}".format(metadata.get("title", "?"), link))


@CommandHandler.register_raw()
def dad_handler(ctx: EchoClient, message: str) -> None:
    """Check if the message starts with 'I'm' or 'im', etc...

    Args:
        ctx (EchoClient): The EchoClient instance.
        message (str): The message.
    """
    if (not message.lower().startswith("i'm") or not
            message.lower().startswith("im")):
        ctx.send("Hi {}, I'm Dad".format(message[3:].strip()))


client = EchoClient("127.0.0.1", 16000)
client.connect()
client.loop()
