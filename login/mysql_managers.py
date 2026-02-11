from django.db import transaction
from django.utils import timezone
from django.db.models import Q
from typing import Optional, List, Dict
from collections import defaultdict
from django.utils.timezone import localtime

from .models import Like, Match, Chat, ChatParticipant, Message

class MySQLLikeManager:
    @staticmethod
    def send_like(from_email: str, to_email: str):
        from_email = from_email.lower()
        to_email = to_email.lower()

        if Like.objects.filter(from_email=from_email, to_email=to_email).exists():
            return {"status": "already_liked"}

        if Like.objects.filter(from_email=to_email, to_email=from_email).exists():
            match = MySQLMatchManager.create_match(from_email, to_email)
            Like.objects.filter(
                Q(from_email=from_email, to_email=to_email) |
                Q(from_email=to_email, to_email=from_email)
            ).delete()
            return {"status": "matched", "match": match}

        Like.objects.create(from_email=from_email, to_email=to_email)
        return {"status": "liked"}

class MySQLMatchManager:
    @staticmethod
    @transaction.atomic
    def create_match(user_a: str, user_b: str):
        users = sorted([user_a.lower(), user_b.lower()])
        user_a, user_b = users

        existing = Match.objects.filter(user_a=user_a, user_b=user_b).select_related("chat").first()
        if existing:
            return {
                "match_id": existing.id,
                "users": users,
                "chat_id": existing.chat.id,
                "status": existing.status,
                "created_at": existing.created_at.isoformat() + "Z",
            }

        chat = MySQLChatManager.create_chat(users)

        match = Match.objects.create(
            user_a=user_a,
            user_b=user_b,
            chat=chat,
        )

        return {
            "match_id": match.id,
            "users": users,
            "chat_id": chat.id,
            "status": match.status,
            "created_at": match.created_at.isoformat() + "Z",
        }
    
        
    @staticmethod
    def get_user_matches(user_email: str) -> List[str]:
        user_email = user_email.lower()

        matches = Match.objects.filter(
            Q(user_a=user_email) | Q(user_b=user_email)
        )

        matched_users = []

        for match in matches:
            if match.user_a == user_email:
                matched_users.append(match.user_b)
            else:
                matched_users.append(match.user_a)

        return matched_users


class MySQLChatManager:

    @staticmethod
    @transaction.atomic
    def create_chat(users: List[str]) -> Chat:
        """
        Creates a chat and its participants.
        users: list of user emails (lowercase)
        """
        chat = Chat.objects.create()

        ChatParticipant.objects.bulk_create([
            ChatParticipant(chat=chat, email=user_email)
            for user_email in users
        ])

        return chat

    @staticmethod
    def get_chat(chat_id: int) -> Optional[Dict]:
        try:
            chat = Chat.objects.get(id=chat_id)
        except Chat.DoesNotExist:
            return None

        participants = list(
            ChatParticipant.objects
            .filter(chat=chat)
            .values_list("email", flat=True)
        )

        return {
            "id": chat.id,
            "participants": participants,
            "created_at": chat.created_at,
            "last_message": chat.last_message,
            "last_message_at": chat.last_message_at,
        }



    @staticmethod
    def get_messages(chat_id: int) -> Dict[str, List[Dict]]:
        messages = (
            Message.objects
            .filter(chat_id=chat_id)
            .order_by("created_at")
        )

        grouped = defaultdict(list)

        for msg in messages:
            date_key = localtime(msg.created_at).date().isoformat()

            grouped[date_key].append({
                "id": msg.id,
                "sender": msg.sender,
                "receiver": msg.receiver,
                "content": msg.content,
                "type": msg.type,
                "created_at": msg.created_at.isoformat(),
                "is_read": msg.is_read,
                "read_at": msg.read_at.isoformat() if msg.read_at else None,
            })

        return grouped


    @staticmethod
    def add_message(chat_id: int, sender: str, receiver: str, content: str):
        chat = Chat.objects.get(id=chat_id)

        Message.objects.create(
            chat=chat,
            sender=sender,
            receiver=receiver,
            content=content,
            type="text",
        )

        chat.last_message = content
        chat.last_message_at = timezone.now()
        chat.save(update_fields=["last_message", "last_message_at"])

    @staticmethod
    def mark_read(chat_id: int, receiver_email: str):
        Message.objects.filter(
            chat_id=chat_id,
            receiver=receiver_email,
            is_read=False
        ).update(
            is_read=True,
            read_at=timezone.now()
        )
