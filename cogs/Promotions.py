import datetime
import discord
import pytz
from discord.ext import commands
from discord import app_commands

from erm import is_staff, management_predicate, is_management, Bot
from utils.constants import BLANK_COLOR
from utils.paginators import SelectPagination, CustomPage
from utils.utils import require_settings, get_roblox_by_username
from menus import Promotion

class Promotions(commands.Cog):
    def __init__(self, bot):
        self.bot: Bot = bot

    async def check_manager_role(self, ctx):
        """Helper method to check if user has manager role from settings"""
        settings = await self.bot.settings.find_by_id(ctx.guild.id)
        if not settings or "infractions" not in settings:
            return False

        manager_roles = settings["infractions"].get("manager_roles", [])
        return any(role.id in manager_roles for role in ctx.author.roles)

    @commands.hybrid_group(name="promotions")
    @is_staff()
    async def promotions(self, ctx: commands.Context):
        """Base command for promotions"""
        if ctx.invoked_subcommand is None:
            return await ctx.send(
                embed=discord.Embed(
                    title="Invalid Subcommand",
                    description="Please specify a valid subcommand.",
                    color=BLANK_COLOR,
                )
            )
        

    @commands.guild_only()
    @commands.hybrid_command(
        name="mypromos",
        description="View your promotions",
        extras={"category": "Promotions"},
    )
    @is_staff()
    @require_settings()
    async def mypromos(self, ctx):
        """View your infractions"""
        settings = await self.bot.settings.find_by_id(ctx.guild.id)
        if not settings:
            return await ctx.send(
                embed=discord.Embed(
                    title="Not Setup",
                    description="Your server is not setup.",
                    color=BLANK_COLOR,
                )
            )

        if not settings.get("promotions"):
            return await ctx.send(
                embed=discord.Embed(
                    title="Not Enabled",
                    description="Promotions are not enabled on this server.",
                    color=BLANK_COLOR,
                )
            )

        promos = []
        async for pr in self.bot.db.promos.find(
            {"guild_id": ctx.guild.id, "user_id": ctx.author.id}
        ).sort("timestamp", -1):
            promos.append(pr)

        if len(promos) == 0:
            return await ctx.send(
                embed=discord.Embed(
                    title="No Promotions",
                    description="You have not been promoted yet.",
                    color=BLANK_COLOR,
                ),
                ephemeral=True,
            )

        def setup_embed() -> discord.Embed:
            embed = discord.Embed(title="Your Promotions", color=BLANK_COLOR)
            embed.set_author(name=ctx.guild.name, icon_url=ctx.guild.icon)
            return embed

        embeds = []
        for p in pr:
            if len(embeds) == 0 or len(embeds[-1].fields) >= 4:
                embeds.append(setup_embed())

            embed = embeds[-1]
            issuer = "System"
            if p.get("issuer_id"):
                issuer = f"<@{p['issuer_id']}>"

            embed.add_field(
                name=f"Promotion #{p.get('_id', 'Unknown')}",
                value=(
                    f"> **New Role:** <@&{p['role']}>\n"
                    f"> **Reason:** {p['reason']}\n"
                    f"> **Issuer:** {issuer}\n"
                    f"> **Date:** <t:{int(p['timestamp'])}:F>\n"
                    f"> **Status:** {'Revoked' if p.get('revoked', False) else 'Active'}"
                ),
                inline=False,
            )

        pages = [
            CustomPage(embeds=[embed], identifier=str(index + 1))
            for index, embed in enumerate(embeds)
        ]

        if len(pages) > 1:
            paginator = SelectPagination(self.bot, ctx.author.id, pages=pages)
            await ctx.send(embed=embeds[0], view=paginator)
        else:
            await ctx.send(embed=embeds[0])

    @commands.guild_only()
    @promotions.command(
        name="view",
        description="View a user's promotions",
        extras={"category": "Promotions"},
    )
    @is_staff()
    @require_settings()
    @app_commands.describe(user="The user to check promotions for")
    async def promos_view(self, ctx, user: discord.Member):
        """View a user's infractions"""
        if user.id != ctx.author.id:
            has_manager_role = await self.check_manager_role(ctx)
            if not has_manager_role and not await management_predicate(ctx):
                return await ctx.send(
                    embed=discord.Embed(
                        title="Permission Denied",
                        description="You need management permissions to view other users' promotions.",
                        color=BLANK_COLOR,
                    )
                )

        settings = await self.bot.settings.find_by_id(ctx.guild.id)
        if not settings:
            return await ctx.send(
                embed=discord.Embed(
                    title="Not Setup",
                    description="Your server is not setup.",
                    color=BLANK_COLOR,
                )
            )

        if not settings.get("promotions"):
            return await ctx.send(
                embed=discord.Embed(
                    title="Not Enabled",
                    description="Promotions are not enabled on this server.",
                    color=BLANK_COLOR,
                )
            )

        target_id = user.id

        promos = []
        async for pr in self.bot.db.promotions.find(
            {"guild_id": ctx.guild.id, "user_id": target_id}
        ).sort("timestamp", -1):
            promos.append(pr)

        if len(promos) == 0:
            return await ctx.send(
                embed=discord.Embed(
                    title="No Infractions",
                    description=f"{'You have' if target_id == ctx.author.id else 'This user has'} no promotions yet.",
                    color=BLANK_COLOR,
                ),
                ephemeral=True,
            )

        def setup_embed() -> discord.Embed:
            name = None
            try:
                if target_id:
                    member = ctx.guild.get_member(target_id)
                    if member:
                        name = member.name
                    else:
                        user = self.bot.get_user(target_id)
                        if user:
                            name = user.name
            except:
                pass

            if not name:
                name = str(target_id)

            embed = discord.Embed(title=f"Promotions for {name}", color=BLANK_COLOR)
            embed.set_author(name=ctx.guild.name, icon_url=ctx.guild.icon)
            return embed

        embeds = []
        for p in promos:
            if len(embeds) == 0 or len(embeds[-1].fields) >= 4:
                embeds.append(setup_embed())

            embed = embeds[-1]
            issuer = "System"
            if p.get("issuer_id"):
                issuer = f"<@{p['issuer_id']}>"

            embed.add_field(
                name=f"Promotion #{p.get('_id', 'Unknown')}",
                value=(
                    f"> **New Role:** <@&{p['role']}>\n"
                    f"> **Reason:** {p['reason']}\n"
                    f"> **Issuer:** {issuer}\n"
                    f"> **Date:** <t:{int(p['timestamp'])}:F>\n"
                    f"> **Status:** {'Revoked' if p.get('revoked', False) else 'Active'}"
                ),
                inline=False,
            )

        pages = [
            CustomPage(embeds=[embed], identifier=str(index + 1))
            for index, embed in enumerate(embeds)
        ]

        if len(pages) > 1:
            paginator = SelectPagination(self.bot, ctx.author.id, pages=pages)
            await ctx.send(embed=embeds[0], view=paginator)
        else:
            await ctx.send(embed=embeds[0])

    @commands.guild_only()
    @promotions.command(name="promote", description="Issue an promotion to a user", extras={"category": "Promotions", "ignoreDefer": True})
    @is_staff()
    @require_settings()
    async def promotion_issue(self, ctx):
        """Issue an infraction to a user"""
        if not ctx.interaction:
            return await ctx.send(
                embed=discord.Embed(
                    title="Not Permitted", 
                    description="Promotions may only be issued from slash commands", 
                    color=BLANK_COLOR
                )
            )
        
        has_manager_role = await self.check_manager_role(ctx)
        if not has_manager_role and not await management_predicate(ctx):
            return await ctx.interaction.response.send_message(
                embed=discord.Embed(
                    title="Permission Denied",
                    description="You need management permissions or your promotions manager permission to issue promotions.",
                    color=BLANK_COLOR,
                ),
                ephemeral=True
            )

        settings = await self.bot.settings.find_by_id(ctx.guild.id)
        if not settings:
            return await ctx.interaction.response.send_message(
                embed=discord.Embed(
                    title="Not Setup",
                    description="Your server is not setup.",
                    color=BLANK_COLOR,
                ),
                ephemeral=True
            )

        if not settings.get("promotions"):
            return await ctx.interaction.response.send_message(
                embed=discord.Embed(
                    title="Not Enabled",
                    description="Promotions are not enabled on this server.",
                    color=BLANK_COLOR,
                ),
                ephemeral=True
            )


        modal = Promotion()
        await ctx.interaction.response.send_modal(modal)

        await modal.wait()

        if not modal.modal_interaction:
            return
        
        user: discord.User

        embed2 = discord.Embed(
                title=f"{self.bot.emoji_controller.get_emoji('success')} Promotion Issued",
                description="Successfully issued an promotion!",
                color=discord.Color.green(),
            )

        for user in modal.users.component.values:
            target_name = user.name
            target_id = user.id
            # Create promotion document
            promo_doc = {
                "user_id": user.id,
                "username": user.name,
                "guild_id": ctx.guild.id,
                "role": modal.role.component.values[0].id,
                "reason": modal.reason.component.value,
                "timestamp": datetime.datetime.now(tz=pytz.UTC).timestamp(),
                "issuer_id": ctx.author.id,
                "issuer_username": ctx.author.name,
            }

            result = await self.bot.db.promotions.insert_one(promo_doc)
            promo_doc["_id"] = result.inserted_id
            embed2.add_field(
                name=f"Details for user {user.name}",
                value=(
                    f"> **User:** {user.name}\n"
                    f"> **New Role:** <@&{modal.role.component.values[0].id}>\n"
                    f"> **Reason:** {modal.reason.component.value}\n"
                    f"> **Notes:** {modal.notes.component.value if modal.notes.component.value != "" else "N/A"}\n"
                    f"> **Issued By:** {ctx.author.mention}\n"
                    f"> **Date:** <t:{int(promo_doc['timestamp'])}:F>\n"
                    f"> **ID:** `{result.inserted_id}`\n"
                ),
                inline=False,
            )
            self.bot.dispatch("promotion_create", promo_doc)

            target_name = str(target_id)
            try:
                member = ctx.guild.get_member(target_id)
                if member:
                    target_name = member.name
                else:
                    user = self.bot.get_user(target_id)
                    if user:
                        target_name = user.name
                    else:
                        roblox_user = await get_roblox_by_username(
                            str(target_id), self.bot, ctx
                        )
                        if roblox_user and not roblox_user.get("errors"):
                            target_name = roblox_user["name"]
            except:
                pass
            embed = discord.Embed(title = "You've been promoted", description=(
                    f"You were promoted in {ctx.guild.name}. Please refer below for more information.\n"
                    f"> **New Role:** {modal.role.component.values[0].name}\n"
                    f"> **Reason:** {modal.reason.component.value}\n"
                    f"> **Notes:** {modal.notes.component.value if modal.notes.component.value != "" else "N/A"}\n"
                    f"> **Issued By:** {ctx.author.mention}\n"
                    f"> **Date:** <t:{int(promo_doc['timestamp'])}:F>\n"
            ))
            try:
                await user.send(embed=embed)
            except Exception:
                pass
        embed = discord.Embed(title = "Promotion Notice", description=(
                    f"These users have received a promotion! Congratulations.\n"
            ), color=discord.Colour.green())
        embed.add_field(name = "User(s)", value = " ".join(user.mention for user in modal.users.component.values), inline=False)
        embed.add_field(name = "New Role", value = f"<@&{modal.role.component.values[0].id}>", inline=False)
        embed.add_field(name = "Reason", value = modal.reason.component.value, inline=False)
        embed.add_field(name = "Notes", value = modal.notes.component.value if modal.notes.component.value != "" else "N/A", inline=False)
        embed.add_field(name = "Issuer", value = ctx.author.mention, inline=False)
        embed.add_field(name = "Date", value = f"<t:{int(promo_doc['timestamp'])}:F>", inline=False)
        channel = discord.utils.get(ctx.guild.channels, id=settings.get("promotions").get("channel", 0))
        await channel.send(" ".join(user.mention for user in modal.users.component.values), embed=embed)

        try:
            await ctx.interaction.followup.send(
                embed=embed2,
                ephemeral=True,
            )
        except discord.InteractionResponded:
            # If the original interaction was already responded to in another path,
            # try editing the original response or fall back to a normal send.
            try:
                await ctx.interaction.edit_original_response(embed=embed)
            except Exception:
                try:
                    await ctx.send(embed=embed)
                except Exception:
                    pass

    @promotions.command(name="revoke", description="Revoke a promotion using its ID")
    @is_staff()
    @require_settings()
    @app_commands.describe(promotion_id="The ID of the promotion to revoke")
    async def infractions_revoke(self, ctx, promotion_id: str):
        """Revoke an infraction"""
        has_manager_role = await self.check_manager_role(ctx)
        if not has_manager_role and not await management_predicate(ctx):
            return await ctx.send(
                embed=discord.Embed(
                    title="Permission Denied",
                    description="You need management permissions to revoke promotions.",
                    color=BLANK_COLOR,
                )
            )

        try:
            from bson import ObjectId

            promotion = await self.bot.db.promotions.find_one(
                {"_id": ObjectId(promotion_id)}
            )
            if not promotion:
                return await ctx.send(
                    embed=discord.Embed(
                        title="Not Found",
                        description="No promotion was found with that ID.",
                        color=BLANK_COLOR,
                    )
                )

            if promotion["guild_id"] != ctx.guild.id:
                return await ctx.send(
                    embed=discord.Embed(
                        title="Not Found",
                        description="No promotion was found with that ID in this server.",
                        color=BLANK_COLOR,
                    )
                )

            if promotion.get("revoked", False):
                return await ctx.send(
                    embed=discord.Embed(
                        title="Already Revoked",
                        description="This promotion has already been revoked.",
                        color=BLANK_COLOR,
                    )
                )

            await self.bot.db.promotions.update_one(
                {"_id": ObjectId(promotion_id)},
                {
                    "$set": {
                        "revoked": True,
                        "revoked_at": datetime.datetime.now(tz=pytz.UTC).timestamp(),
                        "revoked_by": ctx.author.id,
                    }
                },
            )

            promotion["revoked"] = True
            promotion["revoked_at"] = datetime.datetime.now(tz=pytz.UTC).timestamp()
            promotion["revoked_by"] = ctx.author.id
            self.bot.dispatch("promo_revoke", promotion)

            await ctx.send(
                embed=discord.Embed(
                    title=f"{self.bot.emoji_controller.get_emoji('success')} Promotion Revoked",
                    description="Successfully promotion the infraction!",
                    color=discord.Color.green(),
                )
            )

        except Exception as e:
            await ctx.send(
                embed=discord.Embed(
                    title="Error",
                    description=f"An error occurred while revoking the infraction: {str(e)}",
                    color=BLANK_COLOR,
                )
            )


async def setup(bot):
    await bot.add_cog(Promotions(bot))
