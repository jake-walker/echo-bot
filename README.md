# Echo Bot

A bot for providing additional functionality to [Echo v3](https://github.com/will-scargill/Echo-V3) chat.

> **This project is a work-in-progress.** It is not designed for a production environment and regularly breaks.

## Usage

```
pipenv install --dev
pipenv run python main.py
```

## Features

- **Link metadata.** Links are found within any message and the bot will respond with the webpage's title.
- **Dad Jokes.**

### Commands

| Command | Description |
| --- | --- |
| `!ping` | Sends back a pong message. Pass an optional message for the bot to respond with it. |
| `!dice` | Roll a 6-sided dice. Pass an optional number for a different sided dice (e.g. `!dice 12`) |
| `!disconnect` | Make the bot gracefully disconnect from the server. |
