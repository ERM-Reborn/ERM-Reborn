"""
Enhanced Security Module for ERM-Reborn
Provides comprehensive security features including:
- CSRF token generation and validation
- Request signing and verification
- Session management with refresh tokens
- Enhanced authorization and permission checks
- Audit logging
"""

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import datetime
import typing
from collections import defaultdict
from typing import Optional, Dict, Any

import pytz
from decouple import config
from fastapi import HTTPException, Request
from bson import ObjectId

logger = logging.getLogger(__name__)


class CSRFTokenManager:
    """Manages CSRF tokens for state-changing operations"""
    
    def __init__(self, db=None, token_lifetime: int = 3600):
        """
        Initialize CSRF token manager
        
        Args:
            db: MongoDB database connection
            token_lifetime: How long tokens are valid in seconds (default 1 hour)
        """
        self.db = db
        self.token_lifetime = token_lifetime
        self._memory_tokens: Dict[str, Dict[str, Any]] = {}  # Fallback in-memory store
    
    async def generate_token(self, session_id: str, user_id: int, guild_id: int) -> str:
        """Generate a new CSRF token for a user session"""
        token = secrets.token_urlsafe(32)
        expires_at = datetime.datetime.now(tz=pytz.UTC).timestamp() + self.token_lifetime
        
        token_doc = {
            "_id": token,
            "session_id": session_id,
            "user_id": user_id,
            "guild_id": guild_id,
            "created_at": datetime.datetime.now(tz=pytz.UTC).timestamp(),
            "expires_at": expires_at,
            "used": False
        }
        
        # Try to save to database, fall back to memory
        try:
            if self.db is not None:
                await self.db.csrf_tokens.insert_one(token_doc)
            else:
                self._memory_tokens[token] = token_doc
        except Exception as e:
            logger.warning(f"Failed to save CSRF token to DB, using memory: {e}")
            self._memory_tokens[token] = token_doc
        
        return token
    
    async def validate_token(self, token: str, session_id: str, user_id: int) -> bool:
        """Validate a CSRF token"""
        if not token:
            return False
        
        # Check database first
        try:
            if self.db:
                token_doc = await self.db.csrf_tokens.find_one({"_id": token})
            else:
                token_doc = self._memory_tokens.get(token)
            
            if not token_doc:
                return False
            
            # Check if token is expired
            if token_doc["expires_at"] < datetime.datetime.now(tz=pytz.UTC).timestamp():
                return False
            
            # Check if token matches the session and user
            if token_doc["session_id"] != session_id or token_doc["user_id"] != user_id:
                return False
            
            # Check if already used
            if token_doc.get("used"):
                return False
            
            # Mark token as used (single-use)
            try:
                if self.db:
                    await self.db.csrf_tokens.update_one(
                        {"_id": token},
                        {"$set": {"used": True, "used_at": datetime.datetime.now(tz=pytz.UTC).timestamp()}}
                    )
                else:
                    self._memory_tokens[token]["used"] = True
            except Exception as e:
                logger.warning(f"Failed to mark CSRF token as used: {e}")
            
            return True
        except Exception as e:
            logger.error(f"Error validating CSRF token: {e}")
            return False


class RequestSignatureManager:
    """Manages request signing and verification using HMAC"""
    
    def __init__(self, shared_secret: Optional[str] = None):
        """
        Initialize request signature manager
        
        Args:
            shared_secret: Shared secret for signing (if None, uses API_SIGNING_SECRET env var)
        """
        self.shared_secret = shared_secret or config("API_SIGNING_SECRET", default="")
        if not self.shared_secret:
            logger.warning("No API_SIGNING_SECRET configured - request signing disabled")
    
    def sign_request(self, method: str, path: str, body: bytes, timestamp: str) -> str:
        """
        Sign a request using HMAC-SHA256
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            body: Request body as bytes
            timestamp: Request timestamp (ISO format)
        
        Returns:
            Signature string
        """
        if not self.shared_secret:
            return ""
        
        # Create canonical request
        canonical = f"{method}\n{path}\n{timestamp}\n{body.decode() if body else ''}"
        
        # Sign with HMAC-SHA256
        signature = hmac.new(
            self.shared_secret.encode(),
            canonical.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def verify_signature(self, method: str, path: str, body: bytes, 
                        timestamp: str, signature: str, max_age: int = 300) -> bool:
        """
        Verify a request signature
        
        Args:
            method: HTTP method
            path: Request path
            body: Request body as bytes
            timestamp: Request timestamp (ISO format)
            signature: Signature to verify
            max_age: Maximum age of request in seconds (default 5 minutes)
        
        Returns:
            True if signature is valid, False otherwise
        """
        if not self.shared_secret or not signature:
            logger.warning("Cannot verify signature - no secret or signature provided")
            return False
        
        try:
            # Check timestamp is recent enough
            req_time = datetime.datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            now = datetime.datetime.now(tz=pytz.UTC)
            age = (now - req_time).total_seconds()
            
            if age > max_age or age < -30:  # Allow 30 seconds clock skew
                logger.warning(f"Request timestamp too old or in future: {age}s")
                return False
            
            # Calculate expected signature
            expected_signature = self.sign_request(method, path, body, timestamp)
            
            # Use constant-time comparison to prevent timing attacks
            return hmac.compare_digest(signature, expected_signature)
        except Exception as e:
            logger.error(f"Error verifying signature: {e}")
            return False


class SessionManager:
    """Manages secure user sessions with refresh tokens"""
    
    def __init__(self, db=None, session_lifetime: int = 3600, 
                 refresh_lifetime: int = 2592000):
        """
        Initialize session manager
        
        Args:
            db: MongoDB database connection
            session_lifetime: Access token lifetime in seconds (default 1 hour)
            refresh_lifetime: Refresh token lifetime in seconds (default 30 days)
        """
        self.db = db
        self.session_lifetime = session_lifetime
        self.refresh_lifetime = refresh_lifetime
    
    async def create_session(self, user_id: int, guild_id: int, 
                            ip_address: str, user_agent: str) -> Dict[str, Any]:
        """
        Create a new user session with access and refresh tokens
        
        Args:
            user_id: Discord user ID
            guild_id: Guild ID
            ip_address: Client IP address
            user_agent: Client user agent
        
        Returns:
            Dictionary with access_token, refresh_token, and metadata
        """
        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        
        now = datetime.datetime.now(tz=pytz.UTC).timestamp()
        
        session_doc = {
            "_id": access_token,
            "refresh_token": refresh_token,
            "user_id": user_id,
            "guild_id": guild_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "created_at": now,
            "expires_at": now + self.session_lifetime,
            "refresh_expires_at": now + self.refresh_lifetime,
            "active": True,
            "last_activity": now
        }
        
        if self.db:
            try:
                await self.db.sessions.insert_one(session_doc)
            except Exception as e:
                logger.error(f"Failed to create session in DB: {e}")
                raise
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": self.session_lifetime,
            "token_type": "Bearer"
        }
    
    async def validate_session(self, token: str, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Validate a session token
        
        Args:
            token: Access token to validate
            ip_address: Current client IP address
        
        Returns:
            Session data if valid, None otherwise
        """
        if not self.db:
            return None
        
        try:
            session = await self.db.sessions.find_one({"_id": token})
            
            if not session:
                return None
            
            # Check if session is active
            if not session.get("active"):
                return None
            
            # Check if session is expired
            if session["expires_at"] < datetime.datetime.now(tz=pytz.UTC).timestamp():
                await self.db.sessions.update_one(
                    {"_id": token},
                    {"$set": {"active": False}}
                )
                return None
            
            # Check IP address (optional security check - warn if different)
            if session.get("ip_address") != ip_address:
                logger.warning(f"Session IP mismatch for user {session['user_id']}")
                # Note: Not failing here as users may have dynamic IPs, but logging for audit
            
            # Update last activity
            await self.db.sessions.update_one(
                {"_id": token},
                {"$set": {"last_activity": datetime.datetime.now(tz=pytz.UTC).timestamp()}}
            )
            
            return session
        except Exception as e:
            logger.error(f"Error validating session: {e}")
            return None
    
    async def refresh_session(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """
        Refresh an access token using a refresh token
        
        Args:
            refresh_token: Refresh token
        
        Returns:
            New access token if valid, None otherwise
        """
        if not self.db:
            return None
        
        try:
            session = await self.db.sessions.find_one({"refresh_token": refresh_token})
            
            if not session:
                return None
            
            # Check if refresh token is expired
            if session["refresh_expires_at"] < datetime.datetime.now(tz=pytz.UTC).timestamp():
                await self.db.sessions.update_one(
                    {"_id": session["_id"]},
                    {"$set": {"active": False}}
                )
                return None
            
            # Invalidate old token
            old_token = session["_id"]
            await self.db.sessions.update_one(
                {"_id": old_token},
                {"$set": {"active": False}}
            )
            
            # Create new session with same refresh token
            new_access_token = secrets.token_urlsafe(32)
            now = datetime.datetime.now(tz=pytz.UTC).timestamp()
            
            new_session = {
                "_id": new_access_token,
                "refresh_token": refresh_token,
                "user_id": session["user_id"],
                "guild_id": session["guild_id"],
                "ip_address": session["ip_address"],
                "user_agent": session["user_agent"],
                "created_at": now,
                "expires_at": now + self.session_lifetime,
                "refresh_expires_at": session["refresh_expires_at"],
                "active": True,
                "last_activity": now
            }
            
            await self.db.sessions.insert_one(new_session)
            
            return {
                "access_token": new_access_token,
                "refresh_token": refresh_token,
                "expires_in": self.session_lifetime,
                "token_type": "Bearer"
            }
        except Exception as e:
            logger.error(f"Error refreshing session: {e}")
            return None
    
    async def revoke_session(self, token: str) -> bool:
        """Revoke a session token"""
        if not self.db:
            return False
        
        try:
            result = await self.db.sessions.update_one(
                {"_id": token},
                {"$set": {"active": False, "revoked_at": datetime.datetime.now(tz=pytz.UTC).timestamp()}}
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Error revoking session: {e}")
            return False


class PermissionValidator:
    """Validates user permissions for operations"""
    
    @staticmethod
    async def check_guild_access(bot, user_id: int, guild_id: int) -> bool:
        """Check if user has access to guild"""
        try:
            guild = bot.get_guild(guild_id) or await bot.fetch_guild(guild_id)
            member = guild.get_member(user_id) or await guild.fetch_member(user_id)
            return member is not None
        except Exception:
            return False
    
    @staticmethod
    async def check_guild_modification_permission(bot, user_id: int, 
                                                 guild_id: int) -> bool:
        """Check if user can modify guild settings"""
        try:
            guild = bot.get_guild(guild_id) or await bot.fetch_guild(guild_id)
            member = guild.get_member(user_id) or await guild.fetch_member(user_id)
            
            if not member:
                return False
            
            # Check if user is admin or has management permission
            from erm import admin_check, management_check
            
            is_admin = await admin_check(bot, guild, member)
            is_manager = await management_check(bot, guild, member)
            
            return is_admin or is_manager or member.id == guild.owner_id
        except Exception:
            return False
    
    @staticmethod
    async def check_staff_access(bot, user_id: int, guild_id: int) -> bool:
        """Check if user has staff access"""
        try:
            guild = bot.get_guild(guild_id) or await bot.fetch_guild(guild_id)
            member = guild.get_member(user_id) or await guild.fetch_member(user_id)
            
            if not member:
                return False
            
            from erm import staff_check
            return await staff_check(bot, guild, member)
        except Exception:
            return False


class AuditLogger:
    """Logs all data modifications for audit trail"""
    
    def __init__(self, db=None):
        self.db = db
    
    async def log_action(self, action_type: str, user_id: int, guild_id: int,
                        resource_type: str, resource_id: str, 
                        changes: Dict[str, Any], ip_address: str = None,
                        status: str = "success", error: str = None) -> bool:
        """
        Log an action to the audit trail
        
        Args:
            action_type: Type of action (create, update, delete, etc.)
            user_id: User who performed the action
            guild_id: Guild where action occurred
            resource_type: Type of resource modified
            resource_id: ID of resource modified
            changes: Dictionary of changes made
            ip_address: IP address of user
            status: Status of action (success/failure)
            error: Error message if action failed
        
        Returns:
            True if logged successfully
        """
        if not self.db:
            logger.warning("No database connection for audit logging")
            return False
        
        try:
            audit_doc = {
                "_id": ObjectId(),
                "action_type": action_type,
                "user_id": user_id,
                "guild_id": guild_id,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "changes": changes,
                "ip_address": ip_address,
                "status": status,
                "error": error,
                "timestamp": datetime.datetime.now(tz=pytz.UTC),
                "created_at": datetime.datetime.now(tz=pytz.UTC).timestamp()
            }
            
            await self.db.audit_logs.insert_one(audit_doc)
            return True
        except Exception as e:
            logger.error(f"Failed to log audit action: {e}")
            return False
    
    async def get_audit_trail(self, guild_id: int, limit: int = 100,
                             skip: int = 0) -> list:
        """Get audit trail for a guild"""
        if not self.db:
            return []
        
        try:
            logs = []
            async for doc in self.db.audit_logs.find(
                {"guild_id": guild_id}
            ).sort([("timestamp", -1)]).skip(skip).limit(limit):
                doc["_id"] = str(doc["_id"])
                logs.append(doc)
            return logs
        except Exception as e:
            logger.error(f"Failed to get audit trail: {e}")
            return []


class EnhancedRateLimiter:
    """User-based rate limiting with sliding window"""
    
    def __init__(self, max_requests: int = 100, window_size: int = 60):
        """
        Initialize rate limiter
        
        Args:
            max_requests: Max requests per window
            window_size: Window size in seconds
        """
        self.max_requests = max_requests
        self.window_size = window_size
        self._request_log = defaultdict(list)
    
    async def check_limit(self, user_id: int, endpoint: str = None) -> tuple[bool, dict]:
        """
        Check rate limit for user
        
        Args:
            user_id: User to check
            endpoint: Optional endpoint identifier
        
        Returns:
            Tuple of (allowed: bool, info: dict with remaining_requests, reset_time)
        """
        identifier = f"{user_id}:{endpoint or 'default'}"
        now = datetime.datetime.now().timestamp()
        
        # Remove old requests outside window
        self._request_log[identifier] = [
            req_time for req_time in self._request_log[identifier]
            if now - req_time < self.window_size
        ]
        
        request_count = len(self._request_log[identifier])
        
        if request_count >= self.max_requests:
            # Find earliest request to calculate reset time
            reset_time = self._request_log[identifier][0] + self.window_size
            return False, {
                "remaining_requests": 0,
                "reset_time": int(reset_time),
                "retry_after": max(1, int(reset_time - now))
            }
        
        # Record this request
        self._request_log[identifier].append(now)
        
        return True, {
            "remaining_requests": self.max_requests - request_count - 1,
            "reset_time": int(now + self.window_size),
            "retry_after": None
        }


# Initialize global instances
csrf_manager = CSRFTokenManager()
signature_manager = RequestSignatureManager()
session_manager = SessionManager()
rate_limiter = EnhancedRateLimiter(max_requests=100, window_size=60)
permission_validator = PermissionValidator()
audit_logger = AuditLogger()
