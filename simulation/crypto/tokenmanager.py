import jwt
import datetime
import time
from typing import Dict, Optional

SECRET_KEY = "your-secure-secret-key"

class TokenManager:
    @staticmethod
    def create_token(device_id: str, issuer: str, expiration_minutes: int = 60) -> str:
        """
        Create a JWT token.

        Args:
            device_id (str): Unique identifier for the device.
            issuer (str): Issuer of the token.
            expiration_minutes (int): Token expiration time in minutes.

        Returns:
            str: Encoded JWT token.
        """
        payload = {
            "device_id": device_id,
            "issuer": issuer,
            "issued_at": int(time.time()), 
            "expiration_time": int(time.time()) + expiration_minutes * 60
        }
        return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    @staticmethod
    def verify_token(token: str) -> Optional[list[bool, Dict]]:
        """
        Verify a JWT token.

        Args:
            token (str): JWT token to verify.

        Returns:
            Optional[Dict]: Decoded payload if valid, None if invalid.
        """
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            
            if int(time.time()) > decoded["expiration_time"]:
                return [True,decoded]
            return [False,decoded]
        except jwt.ExpiredSignatureError:
            print("Token has expired.")
        except jwt.InvalidTokenError:
            print("Invalid token.")
        return None

    @staticmethod
    def refresh_token(token: str, expiration_minutes: int = 60) -> Optional[str]:
        """
        Refresh an expired JWT token.

        Args:
            token (str): Expired JWT token.
            expiration_minutes (int): New expiration time in minutes.

        Returns:
            Optional[str]: New JWT token if valid, None if invalid.
        """
        status, data = TokenManager.verify_token(token)

        if status:
            return TokenManager.create_token(
                device_id=data["device_id"],
                issuer=data["issuer"],
                expiration_minutes=expiration_minutes
            )

    @staticmethod
    def inject_token(payload: Dict, token: str) -> Dict:
        """
        Add a JWT token to a payload.

        Args:
            payload (Dict): Original payload.
            token (str): JWT token to inject.

        Returns:
            Dict: Payload with token added.
        """
        payload["token"] = token
        return payload

    @staticmethod
    def validate_payload(payload: Dict) -> Optional[Dict]:
        """
        Extract and validate a JWT token from a payload.

        Args:
            payload (Dict): Payload containing the token.

        Returns:
            Optional[Dict]: Decoded token payload if valid, None if invalid.
        """
        token = payload.get("token")
        if not token:
            print("No token found in payload.")
            return None
        return TokenManager.verify_token(token)