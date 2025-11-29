import datetime
from io import BytesIO
import logging
import typing
import asyncio
import discord
import pytz
from decouple import config
from discord import app_commands
from discord.ext import commands
from erm import Bot, is_management, require_settings
import datamodels.Tickets as tk
from utils.utils import get_prefix, interpret_content, interpret_embed, log_command_usage
from menus import TicketConfiguration, TicketDropDown


class Tickets(commands.Cog):
    def __init__(self, bot):
        self.bot: Bot = bot
    
    async def check_categories(self, ctx: commands.Context):
        settings: dict = await self.bot.settings.find_by_id(ctx.guild.id)
        category: dict = next(d for i, d in enumerate(settings["tickets"].get("categories")) if d["id"] == ctx.channel.category.id)
        if any(role.id in category.get("roles", []) for role in ctx.author.roles):
            return True
        else:
            return False
        

    @commands.hybrid_group(name="ticket") 
    async def ticket(self, ctx):
        pass
    

    @ticket.command(name = "pts", description = "Request PTS")
    @commands.guild_only()
    async def _pts(self, ctx: commands.Context):
        settings = await self.bot.settings.find_by_id(ctx.guild.id)
        ticket_settings = settings.get("tickets")
        if not ticket_settings or not ticket_settings.get("enabled", False):
            return await ctx.send(embed=discord.Embed(title = "Not enabled", description="Tickets are not enabled in this server."), ephemeral=True)
        ticket_exists = await self.bot.tickets.fetch_ticket(ctx.channel.id)
        if ticket_exists:
            await ctx.send("Sending PTS message", ephemeral=True)
            embed = discord.Embed(title = "PTS", description = f"{ctx.user.mention} is requesting to speak in this ticket. The owner of the ticket may always deny this request.")
            embed.set_footer(text = "If you are denied PTS permission you cannot talk or risk moderation.")
            await ctx.channel.send(embed=embed)
        else:
            await ctx.send("You're not in a ticket channel!", ephemeral=True)
        
    @ticket.command(name = "add-user", description = "Add a user")
    @commands.has_permissions(moderate_members=True)
    @commands.guild_only()
    async def _add(self, ctx: commands.Context, user: discord.Member):
        settings = await self.bot.settings.find_by_id(ctx.guild.id)
        ticket_settings = settings.get("tickets")
        if not ticket_settings or not ticket_settings.get("enabled", False):
            return await ctx.send(embed=discord.Embed(title = "Not enabled", description="Tickets are not enabled in this server."), ephemeral=True)

        ticket_exists = await self.bot.tickets.fetch_ticket(ctx.channel.id)
        if ticket_exists:
            overwrite: discord.PermissionOverwrite = ctx.channel.overwrites_for(user)
            overwrite.view_channel = True
            await ctx.channel.set_permissions(user, overwrite=overwrite)
            await ctx.send(f"Added {user.mention} to this ticket!", ephemeral=True)
        else:
            await ctx.send("You're not in a ticket channel!", ephemeral=True)
    @ticket.command(name = "remove-user", description = "Remove a user")
    @commands.has_permissions(moderate_members=True)
    @commands.guild_only()
    async def _add(self, ctx: commands.Context, user: discord.Member):
        settings = await self.bot.settings.find_by_id(ctx.guild.id)
        ticket_settings = settings.get("tickets")
        if not ticket_settings or not ticket_settings.get("enabled", False):
            return await ctx.send(embed=discord.Embed(title = "Not enabled", description="Tickets are not enabled in this server."), ephemeral=True)
        ticket_exists = await self.bot.tickets.fetch_ticket(ctx.channel.id)
        if ticket_exists:
            overwrite: discord.PermissionOverwrite = ctx.channel.overwrites_for(user)
            overwrite.view_channel = False
            await ctx.channel.set_permissions(user, overwrite=overwrite)
            await ctx.send(f"Removed {user.mention} from this ticket!", ephemeral=True)
        else:
            await ctx.send("You're not in a ticket channel!", ephemeral=True)
    
    @ticket.command(name = "claim", description="Claim the ticket")
    @commands.guild_only()
    async def _claim(self, ctx: commands.Context):
        settings = await self.bot.settings.find_by_id(ctx.guild.id)
        ticket_settings = settings.get("tickets")
        if not ticket_settings or not ticket_settings.get("enabled", False):
            return await ctx.send(embed=discord.Embed(title = "Not enabled", description="Tickets are not enabled in this server."), ephemeral=True)
        check = await self.check_categories(ctx)
        if not check:
            return await ctx.send(embed=discord.Embed(title = "No permissions", description="You do not have the permissions to do this."), ephemeral=True)        
        ticket_exists = await self.bot.tickets.fetch_ticket(ctx.channel.id)
        if ticket_exists:
            if ticket_exists["claimer"]:
                await ctx.send("This ticket has already been claimed!", ephemeral=True)
            else:
                await self.bot.tickets.claim_ticket(ctx.channel.id, ctx.author.id)
                print("jfdsjafhdsajfsaj")
                await ctx.channel.send(embed=discord.Embed(
                    title = "Ticket Claimed",
                    description=f"{ctx.author.mention} will be handling your ticket."
                ))
                
        else:
            await ctx.send(
                    embed=discord.Embed(
                        title = f"Ticket does not exist",
                        description="This ticket doesn't exist.",
                    ), ephemeral=True
                )
    @ticket.command(name = "close", description="Close the ticket")
    @commands.guild_only()
    async def _close(self, ctx: commands.Context):
        settings = await self.bot.settings.find_by_id(ctx.guild.id)
        ticket_settings = settings.get("tickets")
        if not ticket_settings or not ticket_settings.get("enabled", False):
            return await ctx.send(embed=discord.Embed(title = "Not enabled", description="Tickets are not enabled in this server."), ephemeral=True)
        check = await self.check_categories(ctx)
        if not check:
            return await ctx.send(embed=discord.Embed(title = "No permissions", description="You do not have the permissions to do this."), ephemeral=True)        
        ticket_exists = await self.bot.tickets.fetch_ticket(ctx.channel.id)
        if ticket_exists:
            if ticket_exists["closed"]:
                await ctx.send("This ticket has already been closed!", ephemeral=True)
            else:
                await self.bot.tickets.close_ticket(ctx.channel.id)
                await ctx.channel.send(embed=discord.Embed(
                    title = "Ticket Closed",
                    description=f"{ctx.author.mention} closed the ticket."
                ))
                await ctx.send(
                    embed=discord.Embed(
                        title = f"{self.bot.emoji_controller.get_emoji('success')} Successfully Closed Ticket",
                        description="You have now closed the ticket.",
                        colour=discord.Colour.green()
                    ), ephemeral=True
                )
                if ticket_settings.get("close_and_delete", False):
                    
                    await self.bot.tickets.delete_ticket(ctx.channel.id)
                    await ctx.channel.delete(reason="Ticket closed")
    
    @ticket.command(name = "delete", description="Delete the ticket")
    @commands.guild_only()
    async def _delete(self, ctx: commands.Context):
        settings = await self.bot.settings.find_by_id(ctx.guild.id)
        ticket_settings = settings.get("tickets")
        if not ticket_settings or not ticket_settings.get("enabled", False):
            return await ctx.send(embed=discord.Embed(title = "Not enabled", description="Tickets are not enabled in this server."), ephemeral=True)
        if ticket_settings.get("close_and_delete", False):
            return await ctx.send(embed=discord.Embed(title="Close and Delete Enabled", description="Tickets are automatically deleted when closed. This command is not used in this server."), ephemeral=True)
        check = await self.check_categories(ctx)
        if not check:
            return await ctx.send(embed=discord.Embed(title = "No permissions", description="You do not have the permissions to do this."), ephemeral=True)        
        ticket_exists = await self.bot.tickets.fetch_ticket(ctx.channnel.id)
        if ticket_exists:
            if not ticket_exists["closed"]:
                await ctx.send("This ticket must already be closed to delete it.", ephemeral=True)
            else:
                await self.bot.tickets.delete_ticket(ctx.channel.id)

                await ctx.send(
                    embed=discord.Embed(
                        title = f"{self.bot.emoji_controller.get_emoji('success')} Successfully Deleted Ticket",
                        description="Deleting in 5 seconds.",
                        colour=discord.Colour.green()
                    ), ephemeral=True
                )
                await asyncio.sleep(5)
                await self.bot.tickets.delete_ticket(ctx.channel.id)
                await ctx.channel.delete(reason="Ticket deleted")
    
    @ticket.command(name = "configure", description = "Configure the ticket module.")
    @require_settings()
    @is_management()
    @commands.guild_only()
    async def _config(self, ctx: commands.Context):
        settings = await self.bot.settings.find_by_id(ctx.guild.id)
        await log_command_usage(self.bot, ctx.guild, ctx.author, f"Tickets Configure")

        view = TicketConfiguration(
            self.bot,
            ctx.author.id,
            [
                (
                    "Tickets",
                    [
                        ["CUSTOM_CONF", {"_FIND_BY_LABEL": True}],
                        (
                            "Enabled"
                            if settings.get("tickets", {})
                            .get("enabled", None)
                            is True
                            else "Disabled"
                        ),
                    ],
                ),
                (
                    "Close & Delete",
                    [
                        ["CUSTOM_CONF", {"_FIND_BY_LABEL": True}],
                        (
                            "Enabled"
                            if settings.get("tickets", {})
                            .get("close_and_delete", None)
                            is True
                            else "Disabled"
                        ),
                    ],
                )
            ],
        )
        embed = discord.Embed(
            title = "ERM.lite Ticketing",
            description=(
                "ERM.lite introduces a new feature to the ERM ecosystem - tickets.\n\n"
                "In this area, you are able to enable tickets, and configure ticket categories.\n"
                "For each ticket category, you are capable to configure the allowed access roles for them.\n\n"
                "**Enabled**: Enable the ticket integration\n"
                "**Close & Delete**: Close and delete automatically deletes the ticket when it's closed.\n"
            )
        )
        await ctx.send(embed=embed, view=view)
    @ticket.command(
        name = 'message',
        description = 'Send the assistance message',
        hidden=True
    )
    @require_settings()
    @is_management()
    @commands.guild_only()
    async def _assistance_message(self, ctx: commands.Context):
        settings = await self.bot.settings.find_by_id(ctx.guild.id)
        ticket_settings = settings.get("tickets")
        if not ticket_settings or not ticket_settings.get("enabled", False):
            return await ctx.send(embed=discord.Embed(title = "Not enabled", description="Tickets are not enabled in this server."), ephemeral=True)
        
        sett = await self.bot.settings.find_by_id(ctx.guild.id)
        embed = discord.Embed(
            title = sett.get("tickets")["message_title"],
            description = sett.get("tickets")["message_title"]
        )
        view = discord.ui.View(timeout=None)
        view.add_item(TicketDropDown(self.bot, ticket_settings))
        await ctx.message.delete()
        await ctx.channel.send(embed=embed, view=view)
async def setup(bot: Bot):
    view = discord.ui.View(timeout=None)
    view.add_item(TicketDropDown(bot, {"enabled": True, "close_and_delete": True, "categories": [{"id": 0, "name": "temporary", "roles": []}]}))
    bot.add_view(view)
    await bot.add_cog(Tickets(bot))