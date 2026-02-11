from rest_framework import serializers
from .models import Match, Message, Notification
from admin_panel.models import UserReport
from django.contrib.auth import get_user_model
from profiles.models import UserProfile
from django.db.models import Q

User = get_user_model()


class MatchSerializer(serializers.ModelSerializer):
    partner = serializers.SerializerMethodField()

    class Meta:
        model = Match
        fields = ['id', 'partner', 'created_at']

    def get_partner(self, obj):
        request = self.context.get('request')
        if not request:
            return None

        partner = obj.users.exclude(id=request.user.id).first()

        if partner and hasattr(partner, 'profile'):
            photos = partner.profile.photos
            photo_url = None

            if photos and isinstance(photos, list) and len(photos) > 0:
                photo_url = photos[0]
            elif photos and isinstance(photos, str):
                photo_url = photos

            return {
                'id': partner.id,
                'name': partner.profile.first_name,
                'photo': photo_url,
                'bio': partner.profile.bio
            }
        return None


class MessageSerializer(serializers.ModelSerializer):
    is_me = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = ['id', 'content', 'created_at', 'is_me', 'is_read']

    def get_is_me(self, obj):
        request = self.context.get('request')
        if request and request.user:
            # Message.sender is an EmailField, so compare against email/username
            return obj.sender == (request.user.email or request.user.username)
        return False


class CreateUserReportSerializer(serializers.Serializer):
    chat_id = serializers.IntegerField()
    reason = serializers.CharField()
    description = serializers.CharField(required=False)


# ---------- Notification Serializer ----------

class NotificationSerializer(serializers.ModelSerializer):
    """
    Serializes a Notification with enriched context resolved
    entirely from SQL — no Firebase calls.

    Fields:
        id, type, is_read, created_at  — direct from Notification model
        chat_id, match_id              — for frontend routing
        other_user                     — lightweight profile of the
                                         other participant in the match
    """

    other_user = serializers.SerializerMethodField()
    match_id = serializers.SerializerMethodField()

    class Meta:
        model = Notification
        fields = [
            "id",
            "type",
            "is_read",
            "created_at",
            "chat_id",
            "match_id",
            "other_user",
        ]
        read_only_fields = fields

    def get_match_id(self, obj: Notification) -> int | None:
        # obj.match_id is the raw FK integer — no extra query
        return obj.match_id

    def get_other_user(self, obj: Notification) -> dict | None:
        """
        Resolves the other participant's SQL UserProfile.
        Match.user_a / user_b are EmailFields, so we look up
        UserProfile via user__email or user__username.
        """
        if not obj.match:
            return None

        my_email = obj.user.lower()

        if obj.match.user_a.lower() == my_email:
            other_email = obj.match.user_b.lower()
        elif obj.match.user_b.lower() == my_email:
            other_email = obj.match.user_a.lower()
        else:
            return None

        try:
            profile = UserProfile.objects.select_related("user").get(
                Q(user__email=other_email) | Q(user__username=other_email)
            )
        except UserProfile.DoesNotExist:
            return None

        photos = profile.photos or []
        photo_url = photos[0] if isinstance(photos, list) and photos else None

        return {
            "email": other_email,
            "first_name": profile.first_name,
            "photo": photo_url,
            "age": profile.age,
            "bio": profile.bio,
        }