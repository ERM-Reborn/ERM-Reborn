import datetime
import asyncio
import logging
from typing import Optional

import aiohttp
from bson import ObjectId
from discord.ext import commands
import discord
from utils.mongo import Document
from decouple import config

from utils.basedataclass import BaseDataClass

class Ticket:
    user_id: int
    id: int
    claimer: int
    closed: bool
    deleted: bool
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class Tickets(Document):
    def __init__(self, connection, current_tickets):
        self.tickets = Document(connection, current_tickets)
    async def fetch_ticket(self, object_id: ObjectId) -> Optional[Ticket]:
        ticket = await self.tickets.find_by_id(object_id)
        if not ticket:
            return None
        return {
            "id": ticket["_id"],
            "user_id": ticket["user_id"],
            "claimer": ticket["claimer"],
            "closed": ticket["closed"],
            "deleted": ticket["deleted"]
        }
    async def create_ticket(
        self,
        user_id: int,
        ticket_id: int

    ):
        data = {
            "_id": ticket_id,
            "user_id": user_id,
            "claimer": None,
            "closed": False,
            "deleted": False
        }

        await self.tickets.db.insert_one(data)

        
        return data["_id"]


    async def close_ticket(
        self, ticket_id: int
    ):
        
        document = await self.tickets.db.find_one({"_id": ticket_id})
        if not document:
            raise ValueError("Ticket not found.")
        if document["closed"]:
            return False
        document["closed"] = True

        await self.tickets.update_by_id(document)
        return document
    async def delete_ticket(
        self, ticket_id: int
    ):
        
        document = await self.tickets.db.find_one({"_id": ticket_id})
        if not document:
            raise ValueError("Ticket not found.")
        
        # The ticket should be closed before deleting to avoid some... issues. 
        if not document["closed"]:
            return False
        
        document["deleted"] = True

        await self.tickets.db.delete_one(document)
        return document
    
    async def claim_ticket(
        self, ticket_id: int, user_id: int
    ):
        # NOTE: this function is independent if the user has claimed it; This will be handled on the client-end.
        document = await self.tickets.db.find_one({"_id": ticket_id})
        if not document:
            raise ValueError("Ticket not found.")
        
        if document["closed"]:
            return False
        
        document["claimer"] = user_id

        await self.tickets.update_by_id(document)
        return document
    async def reopen_ticket(
        self, ticket_id: int
    ):
        # NOTE: this function is independent if the user has claimed it; This will be handled on the client-end.
        document = await self.tickets.db.find_one({"_id": ticket_id})
        if not document:
            raise ValueError("Ticket not found.")
        
        if not document["closed"]:
            return False
        
        document["closed"] = False

        await self.tickets.update_by_id(document)
        return document
    async def get_ticket_claimer(
        self, ticket_id: int
    ):
        # NOTE: this function is independent if the user has claimed it; This will be handled on the client-end.
        document = await self.tickets.db.find_one({"_id": ticket_id})
        if not document:
            raise ValueError("Ticket not found.")
        if document["claimer"] == None:
            return 0
        
        return int(document["claimer"])
    pass


    