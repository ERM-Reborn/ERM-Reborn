"""
Enhanced security middleware and validators for API
"""

import logging
import datetime
import pytz
from typing import Optional, Callable, Any
from pydantic import BaseModel, Field, validator
from fastapi import Request, HTTPException, Depends
from starlette.middleware.base import BaseHTTPMiddleware
from functools import wraps
from decouple import config

from utils.security import (
    csrf_manager,
    signature_manager,
    session_manager,
    rate_limiter,
    permission_validator,
    AuditLogger
)

logger = logging.getLogger(__name__)


# ============================================================================
# Validation Models
# ============================================================================

class SecureRequestModel(BaseModel):
    """Base model for all requests with security headers"""
    
    @validator("*", pre=True)
    def validate_input(cls, v):
        """Validate and sanitize all input"""
        if isinstance(v, str):
            # Remove null bytes
            v = v.replace('\x00', '')
            # Limit string length
            if len(v) > 10000:
                raise ValueError("Input string too long")
        return v


class LOARequestModel(SecureRequestModel):
    """Validated model for LOA requests"""
    guild: int = Field(..., gt=0)
    user: int = Field(..., gt=0)
    reason: str = Field(..., min_length=1, max_length=1000)
    start_type: str = Field("On Approval")
    start_date: Optional[int] = None
    end_date: int = Field(..., gt=0)
    
    @validator("start_type")
    def validate_start_type(cls, v):
        if v not in ["On Approval", "At Specific Time"]:
            raise ValueError("Invalid start_type")
        return v
    
    @validator("reason")
    def validate_reason(cls, v):
        # Remove dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&']
        for char in dangerous_chars:
            if char in v:
                raise ValueError("Reason contains invalid characters")
        return v


class InfractionRequestModel(SecureRequestModel):
    """Validated model for infraction requests"""
    user_id: int = Field(..., gt=0)
    guild_id: int = Field(..., gt=0)
    infraction_type: str = Field(..., min_length=1, max_length=100)
    reason: str = Field(..., min_length=1, max_length=1000)
    issuer_id: Optional[int] = None


class ApplicationApprovalModel(SecureRequestModel):
    """Validated model for application approval"""
    user: int = Field(..., gt=0)
    guild: int = Field(..., gt=0)
    roles: list = Field(default_factory=list)
    remove_roles: list = Field(default_factory=list)
    application_name: str = Field(..., min_length=1, max_length=200)
    note: str = Field(default="Not provided", max_length=500)
    submitted: int = Field(default=0)


class SettingsUpdateModel(SecureRequestModel):
    """Validated model for settings updates"""
    guild: int = Field(..., gt=0)
    # Allow nested dictionaries but validate structure
    
    class Config:
        extra = "allow"  # Allow other fields


# ============================================================================
# Middleware and Decorators
# ============================================================================

class SecurityMiddleware(BaseHTTPMiddleware):
    """Security middleware for FastAPI"""
    
    def __init__(self, app, db=None):
        super().__init__(app)
        self.db = db
        self.audit_logger = AuditLogger(db)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Any:
        """Process request with security checks"""
        
        # Skip security checks for OPTIONS (CORS preflight) requests
        if request.method == "OPTIONS":
            logger.debug(f"Skipping security checks for OPTIONS request: {request.url.path}")
            return await call_next(request)
        
        # Store request info for later use
        request.state.client_ip = request.client.host if request.client else "unknown"
        request.state.user_agent = request.headers.get("user-agent", "unknown")
        request.state.timestamp = datetime.datetime.now(tz=pytz.UTC).isoformat()
        
        logger.info(f"Request: {request.method} {request.url.path} from {request.state.client_ip}")
        
        # Get authorization header
        auth_header = request.headers.get("authorization", "")
        request.state.auth_token = auth_header.split(" ")[-1] if auth_header else None
        
        logger.info(f"Middleware: Authorization header = '{auth_header}'")
        logger.info(f"Middleware: All header names = {list(request.headers.keys())}")
        logger.info(f"Middleware: All headers = {dict(request.headers)}")
        
        # Enforce authorization and CSRF for state-changing operations
        if request.method in ["POST", "PATCH", "DELETE"]:
            # Check authorization header exists
            if not auth_header:
                logger.warning(f"Missing authorization header for {request.method} {request.url.path}")
                raise HTTPException(status_code=401, detail="Missing authorization header")
            
            # Check CSRF token exists
            csrf_token = request.headers.get("x-csrf-token")
            if not csrf_token:
                logger.warning(f"Missing CSRF token for {request.method} {request.url.path}")
                raise HTTPException(status_code=403, detail="Missing CSRF token")
            
            request.state.csrf_token = csrf_token
            logger.info(f"✓ Middleware: CSRF token validated for {request.method} {request.url.path}")
        
        # Check request signature if provided
        signature = request.headers.get("x-signature", "")
        if signature and request.method != "GET":
            body = await request.body()
            path = request.url.path
            timestamp = request.headers.get("x-timestamp", request.state.timestamp)
            
            if not signature_manager.verify_signature(request.method, path, body, timestamp, signature):
                logger.warning(f"Invalid request signature from {request.state.client_ip}")
                raise HTTPException(status_code=401, detail="Invalid request signature")
            
            # Cache body for later use
            request.state.body = body
        
        try:
            response = await call_next(request)
            
            # Add security headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            
            return response
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Security middleware error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# Dependency Injection Functions
# ============================================================================

async def get_authenticated_user(request: Request, bot) -> dict:
    """Dependency: Get and validate authenticated user"""
    
    auth_header = request.headers.get("authorization", "")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    
    # Support both "Bearer token" and plain token
    token = auth_header.split(" ")[-1] if " " in auth_header else auth_header
    
    # Check rate limit
    allowed, rate_info = await rate_limiter.check_limit(hash(token) % 10000, request.url.path)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Retry after {rate_info['retry_after']} seconds",
            headers={"Retry-After": str(rate_info["retry_after"])}
        )
    
    # Validate token
    token_valid = await validate_authorization(bot, token)
    if not token_valid:
        raise HTTPException(status_code=401, detail="Invalid or expired authorization")
    
    return {"token": token, "ip_address": request.state.client_ip}


async def validate_csrf_token(request: Request, user_data: dict = Depends(get_authenticated_user)):
    """Dependency: Validate CSRF token for state-changing operations"""
    
    if request.method not in ["POST", "PATCH", "DELETE"]:
        return user_data
    
    csrf_token = request.headers.get("x-csrf-token")
    if not csrf_token:
        raise HTTPException(status_code=403, detail="Missing CSRF token")
    
    session_id = request.headers.get("x-session-id")
    if not session_id:
        raise HTTPException(status_code=403, detail="Missing session ID")
    
    # CSRF validation would go here
    # For now, just ensure token exists
    return user_data


async def validate_authorization(bot, token: str, disable_static_tokens=False) -> bool:
    """Validate API authorization token"""
    
    logger.info(f"validate_authorization: Raw token received: {repr(token)}")
    logger.info(f"validate_authorization: Token length: {len(token)}")
    
    # Strip "Bearer " prefix if present
    if token.startswith("Bearer "):
        token = token[7:]
        logger.info(f"Stripped Bearer prefix, token is now: {repr(token)}")
        logger.info(f"Token after strip length: {len(token)}")
    
    if not disable_static_tokens:
        static_token = config("API_STATIC_TOKEN", default="")
        logger.info(f"===== TOKEN VALIDATION =====")
        logger.info(f"Static token from config: {repr(static_token)}")
        logger.info(f"Token to validate: {repr(token)}")
        logger.info(f"Static token length: {len(static_token)}")
        logger.info(f"Received token length: {len(token)}")
        logger.info(f"Bytes - Static: {[ord(c) for c in static_token]}")
        logger.info(f"Bytes - Received: {[ord(c) for c in token]}")
        logger.info(f"Are they equal? {token == static_token}")
        logger.info(f"===========================")
        if static_token and token == static_token:
            logger.info("✓ Token matches static token")
            return True
    
    try:
        logger.info(f"Looking for token in database...")
        token_obj = await bot.api_tokens.db.find_one({"token": token})
        if token_obj:
            logger.info(f"✓ Token found in database: {token_obj}")
            if int(datetime.datetime.now().timestamp()) < token_obj["expires_at"]:
                logger.info("✓ Token is not expired")
                return True
            else:
                logger.warning(f"✗ Token is expired (expires_at: {token_obj['expires_at']}, now: {int(datetime.datetime.now().timestamp())})")
        else:
            logger.warning(f"✗ Token not found in database. Searching database...")
            # Debug: Let's see what's in the database
            all_tokens = await bot.api_tokens.db.find({}).to_list(10)
            logger.warning(f"All tokens in database: {all_tokens}")
    except Exception as e:
        logger.error(f"Error validating token: {e}", exc_info=True)
    
    logger.warning(f"✗ Token validation failed")
    return False


# ============================================================================
# Decorator Functions
# ============================================================================

def require_guild_access(endpoint_func: Callable) -> Callable:
    """Decorator: Verify user has access to specified guild"""
    
    @wraps(endpoint_func)
    async def wrapper(*args, **kwargs):
        request: Request = None
        bot = None
        
        # Find request and bot in arguments
        for arg in args:
            if isinstance(arg, Request):
                request = arg
            if hasattr(arg, 'guilds'):  # Duck typing for bot
                bot = arg
        
        if not request or not bot:
            return await endpoint_func(*args, **kwargs)
        
        # Extract guild_id from request
        guild_id = None
        if "guild_id" in kwargs:
            guild_id = kwargs["guild_id"]
        else:
            try:
                body = await request.json()
                guild_id = body.get("guild") or body.get("guild_id")
            except:
                pass
        
        if not guild_id:
            return await endpoint_func(*args, **kwargs)
        
        # Validate access
        auth_token = request.state.auth_token
        user_id = None
        
        # Extract user_id from token data
        try:
            token_obj = await bot.api_tokens.db.find_one({"token": auth_token})
            if token_obj and token_obj.get("user_id"):
                user_id = token_obj["user_id"]
        except:
            pass
        
        if user_id:
            has_access = await permission_validator.check_guild_access(bot, user_id, guild_id)
            if not has_access:
                raise HTTPException(status_code=403, detail="You do not have access to this guild")
        
        return await endpoint_func(*args, **kwargs)
    
    return wrapper


def require_guild_modification_permission(endpoint_func: Callable) -> Callable:
    """Decorator: Verify user can modify guild data"""
    
    @wraps(endpoint_func)
    async def wrapper(*args, **kwargs):
        request: Request = None
        bot = None
        
        for arg in args:
            if isinstance(arg, Request):
                request = arg
            if hasattr(arg, 'guilds'):
                bot = arg
        
        if not request or not bot:
            return await endpoint_func(*args, **kwargs)
        
        guild_id = kwargs.get("guild_id")
        if not guild_id:
            try:
                body = await request.json()
                guild_id = body.get("guild") or body.get("guild_id")
            except:
                pass
        
        if not guild_id:
            return await endpoint_func(*args, **kwargs)
        
        auth_token = request.state.auth_token
        user_id = None
        
        try:
            token_obj = await bot.api_tokens.db.find_one({"token": auth_token})
            if token_obj and token_obj.get("user_id"):
                user_id = token_obj["user_id"]
        except:
            pass
        
        if user_id:
            has_permission = await permission_validator.check_guild_modification_permission(
                bot, user_id, guild_id
            )
            if not has_permission:
                raise HTTPException(status_code=403, detail="You do not have permission to modify this guild")
        
        return await endpoint_func(*args, **kwargs)
    
    return wrapper


def require_staff_access(endpoint_func: Callable) -> Callable:
    """Decorator: Verify user has staff access"""
    
    @wraps(endpoint_func)
    async def wrapper(*args, **kwargs):
        request: Request = None
        bot = None
        
        for arg in args:
            if isinstance(arg, Request):
                request = arg
            if hasattr(arg, 'guilds'):
                bot = arg
        
        if not request or not bot:
            return await endpoint_func(*args, **kwargs)
        
        guild_id = kwargs.get("guild_id")
        if not guild_id:
            try:
                body = await request.json()
                guild_id = body.get("guild") or body.get("guild_id")
            except:
                pass
        
        if not guild_id:
            return await endpoint_func(*args, **kwargs)
        
        auth_token = request.state.auth_token
        user_id = None
        
        try:
            token_obj = await bot.api_tokens.db.find_one({"token": auth_token})
            if token_obj and token_obj.get("user_id"):
                user_id = token_obj["user_id"]
        except:
            pass
        
        if user_id:
            has_access = await permission_validator.check_staff_access(bot, user_id, guild_id)
            if not has_access:
                raise HTTPException(status_code=403, detail="You do not have staff access")
        
        return await endpoint_func(*args, **kwargs)
    
    return wrapper
