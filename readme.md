# ERM
This is a copy of ERM's source for anyone to self host it during the ERM outage

## About the outage
Recently, a user apart of ERM's dev team attempted to remotely shutdown ERM. The user was quickly caught and was banned, and the bot token was reset so ERM could not be used. The problem is that only the owner of the bot (Mikey) has access to the source code and the capability to reset the bot's token, and Mikey has been unresponsive for about a month. Therefore, the bot is not capable to run.

## How do I install this version of erm?
1. Make sure you have a stable internet connect and [Python](https://python.org) (with pip) installed before you continue
2. Run `pip install -r requirements.txt` to install the dependencies required for ERM to run
3. Fill out the .env.template file and then rename it to .env.
3.1. Please ensure that **ALL** the intents are enabled for the bot or it will not run.
4. Run `python main.py` to execute the bot. 


## Patched items:
1. The Authorization and User-Agent headers were removed due to the bot failing to read API keys if they were on
2. Fixed the unavailability of autocomplete in `/punish`
3. Fixed the issues with `/duty manage` where the embed would not update, and roles would not be assigned.
4. Allowed global sync regardless of what environment
5. Disabled Jishaku (DO NOT RE-ENABLE IT)
6. Added staff request configuration (it was omitted for some reason)


## Extra information

| Item | Notes |
|------|-------|
| Error: WEATHER_SERVICE_URL not defined | Ignore this. It is not required and does not impact the bot's functionality |



