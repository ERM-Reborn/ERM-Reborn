from discord.ext import tasks
import discord
import logging


@tasks.loop(hours=1)
async def change_status(bot):
    await bot.wait_until_ready()
    logging.info("Changing status")
    status = "ermdotlite.sockycat.net ⚡ /about"
    await bot.change_presence(activity=discord.CustomActivity(name=status), status=discord.Status.dnd)
