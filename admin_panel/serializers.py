from rest_framework import serializers
from django.contrib.auth.models import User
from profiles.models import UserProfile
from .models import FooterSection, FooterLink, FooterSettings
from .models import UserReport, AdminAction, PremiumPlan, PremiumFeature, ExpertTip, Review, AdminRole,PromoCode, PromoCodeUsage
import logging

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# REVIEW SERIALIZERS
# ─────────────────────────────────────────────────────────────────────────────

class ReviewSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    reviewed_by_username = serializers.CharField(
        source='reviewed_by.username', read_only=True, allow_null=True
    )

    class Meta:
        model = Review
        fields = [
            'id', 'user', 'username', 'rating', 'text', 'status',
            'created_at', 'reviewed_at', 'reviewed_by',
            'reviewed_by_username', 'admin_notes'
        ]
        read_only_fields = ['user', 'reviewed_by', 'reviewed_at']


class ApprovedReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Review
        fields = ['id', 'rating', 'text', 'created_at']


# ─────────────────────────────────────────────────────────────────────────────
# PREMIUM SERIALIZERS
# ─────────────────────────────────────────────────────────────────────────────

class PremiumPlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = PremiumPlan
        fields = [
            'plan_id', 'name', 'duration', 'plan_type', 'price',
            'original_price', 'price_per_month', 'discount_text',
            'icon', 'color', 'gradient', 'popular', 'features',
            'active', 'display_order', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']

    def validate_price(self, value):
        if value <= 0:
            raise serializers.ValidationError("Price must be greater than 0")
        return value

    def validate(self, attrs):
        if attrs.get('original_price') and attrs.get('price'):
            if attrs['original_price'] <= attrs['price']:
                raise serializers.ValidationError(
                    "Original price must be greater than current price"
                )
        return attrs

class PremiumFeatureSerializer(serializers.ModelSerializer):
    class Meta:
        model = PremiumFeature
        fields = [
                'id', 'title', 'description', 'icon',
                'active', 'display_order', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']

# ... (Keep UserSerializer, UserProfileSerializer, UserReportSerializer, AdminActionSerializer, UserActionSerializer exactly as they were) ...
# (Just paste the rest of your original serializers.py file here)

# ─────────────────────────────────────────────────────────────────────────────
# USER / REPORT / ACTION SERIALIZERS
# ─────────────────────────────────────────────────────────────────────────────

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'date_joined', 'is_active']
        read_only_fields = ['id', 'date_joined']

class UserProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.CharField(source='user.email', read_only=True)

    class Meta:
        model = UserProfile
        fields = [
            'user', 'username', 'email', 'phone', 'gender', 'age',
            'location', 'status', 'account_status', 'join_date', 'last_active',
            'active_time', 'matches', 'messages', 'photo_count', 'reports',
            'profile_complete', 'verified', 'premium', 'first_name',
            'date_of_birth', 'bio', 'interests'
        ]
        read_only_fields = ['join_date', 'last_active', 'age', 'photo_count', 'profile_complete']

class UserReportSerializer(serializers.ModelSerializer):
    reporter_username = serializers.CharField(source='reporter.username', read_only=True)
    reported_username = serializers.CharField(source='reported_user.username', read_only=True)
    reviewed_by_username = serializers.CharField(source='reviewed_by.username', read_only=True, allow_null=True)

    class Meta:
        model = UserReport
        fields = [
            'id', 'reporter', 'reporter_username', 'reported_user',
            'reported_username', 'reason', 'description', 'status',
            'created_at', 'reviewed_at', 'reviewed_by', 'reviewed_by_username',
            'admin_notes'
        ]
        read_only_fields = ['id', 'created_at', 'reviewed_at', 'reviewed_by']

class AdminActionSerializer(serializers.ModelSerializer):
    admin_username = serializers.CharField(source='admin.username', read_only=True)
    target_username = serializers.CharField(source='target_user.username', read_only=True)

    class Meta:
        model = AdminAction
        fields = [
            'id', 'admin', 'admin_username', 'target_user', 'target_username',
            'action_type', 'reason', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']

class UserActionSerializer(serializers.Serializer):
    ACTION_CHOICES = [
        ('suspend', 'Suspend'), ('ban', 'Ban'), ('activate', 'Activate'),
        ('delete', 'Delete'), ('verify', 'Verify'),
    ]
    action = serializers.ChoiceField(choices=ACTION_CHOICES, required=True)
    reason = serializers.CharField(required=False, allow_blank=True, max_length=500)

    def validate_action(self, value):
        if value not in dict(self.ACTION_CHOICES):
            raise serializers.ValidationError(f"Invalid action: {value}")
        return value


# ─────────────────────────────────────────────────────────────────────────────
# EXPERT TIP SERIALIZER
# ─────────────────────────────────────────────────────────────────────────────

class ExpertTipSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExpertTip
        fields = [
            'id', 'name', 'role', 'image', 'tip',
            'icon', 'icon_color', 'bg_color',
            'active', 'display_order', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']

    def validate_image(self, value):
        if not value.startswith(('http://', 'https://')):
            raise serializers.ValidationError("Image must be a valid URL starting with http:// or https://")
        return value


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN ROLE SERIALIZERS - WITH SOFT DELETE SUPPORT
# ─────────────────────────────────────────────────────────────────────────────

VALID_SECTIONS = {'overview', 'users', 'reports', 'analytics', 'premium', 'expert-tips', 'reviews'}
VALID_LEVELS = {'none', 'view', 'edit'}


class AdminRoleSerializer(serializers.ModelSerializer):
    """
    Full read/write serializer for AdminRole with soft delete support.
    """
    # Read-only flattened fields from the linked User
    email = serializers.CharField(source='user.email', read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    
    # Password tracking fields
    initial_password = serializers.CharField(read_only=True, required=False, allow_null=True)
    password_changed = serializers.BooleanField(read_only=True, required=False)
    last_login = serializers.DateTimeField(read_only=True, allow_null=True)
    
    # ✅ NEW: Soft delete tracking
    deleted_at = serializers.DateTimeField(read_only=True, allow_null=True)

    class Meta:
        model = AdminRole
        fields = [
            'id',
            'email',
            'username',
            'role_name',
            'is_super_admin',
            'is_active',
            'permissions',
            'invite_token',
            'invite_accepted',
            'created_at',
            'last_login',
            'initial_password',
            'password_changed',
            'deleted_at',          # ✅ NEW: Track deletion time
        ]
        read_only_fields = [
            'id',
            'email',
            'username',
            'is_super_admin',
            'invite_token',
            'invite_accepted',
            'created_at',
            'last_login',
            'initial_password',
            'password_changed',
            'deleted_at',
        ]

    def validate_permissions(self, value):
        if not isinstance(value, dict):
            raise serializers.ValidationError('permissions must be a JSON object.')
        for key, level in value.items():
            if key not in VALID_SECTIONS:
                raise serializers.ValidationError(f'Unknown section: "{key}".')
            if level not in VALID_LEVELS:
                raise serializers.ValidationError(
                    f'Invalid level "{level}" for section "{key}". Use: none, view, edit.'
                )
        # Fill in any missing sections as 'none'
        for section in VALID_SECTIONS:
            value.setdefault(section, 'none')
        return value


class AdminRoleCreateSerializer(serializers.Serializer):
    """
    Write-only serializer for creating new admin accounts.
    
    ✅ SOFT DELETE: Only checks for ACTIVE users, allowing reuse of 
    usernames/emails from soft-deleted accounts.
    """
    email = serializers.EmailField(required=True)
    username = serializers.CharField(required=True, max_length=150)
    role_name = serializers.CharField(required=True, max_length=100)
    permissions = serializers.DictField(required=True)

    def validate_username(self, value):
        """
        ✅ SOFT DELETE: Only check for ACTIVE users with this username.
        
        Inactive (soft-deleted) users are excluded from uniqueness check,
        allowing the username to be reused.
        """
        # Check if any ACTIVE user has this username
        active_user_exists = User.objects.filter(
            username=value,
            is_active=True
        ).exists()
        
        if active_user_exists:
            raise serializers.ValidationError(
                'This username is already in use by an active admin account.'
            )
        
        # Check if there's an inactive user (for informational purposes)
        inactive_user = User.objects.filter(
            username=value,
            is_active=False
        ).first()
        
        if inactive_user:
            # Log this for debugging
            logger.info(
                f"Username '{value}' belongs to an inactive user. "
                f"Will reactivate or create new account."
            )
        
        return value

    def validate_email(self, value):
        """
        ✅ SOFT DELETE: Only check for ACTIVE users with this email.
        
        Inactive (soft-deleted) users are excluded from uniqueness check,
        allowing the email to be reused.
        """
        # Check if any ACTIVE user has this email
        active_user_exists = User.objects.filter(
            email=value,
            is_active=True
        ).exists()
        
        if active_user_exists:
            raise serializers.ValidationError(
                'This email is already in use by an active admin account.'
            )
        
        # Check if there's an inactive user (for informational purposes)
        inactive_user = User.objects.filter(
            email=value,
            is_active=False
        ).first()
        
        if inactive_user:
            # Log this for debugging
            logger.info(
                f"Email '{value}' belongs to an inactive user. "
                f"Will reactivate or create new account."
            )
        
        return value

    def validate_permissions(self, value):
        if not isinstance(value, dict):
            raise serializers.ValidationError('permissions must be a JSON object.')
        for key, level in value.items():
            if key not in VALID_SECTIONS:
                raise serializers.ValidationError(f'Unknown section: "{key}".')
            if level not in VALID_LEVELS:
                raise serializers.ValidationError(
                    f'Invalid level "{level}" for section "{key}". Use: none, view, edit.'
                )
        # Ensure at least one section has access
        if all(v == 'none' for v in value.values()):
            raise serializers.ValidationError('Grant at least one section permission.')
        # Fill missing sections
        for section in VALID_SECTIONS:
            value.setdefault(section, 'none')
        return value


class DeletedAdminRoleSerializer(serializers.ModelSerializer):
    """
    ✅ NEW: Specialized serializer for viewing deleted admin accounts.
    
    Shows additional information useful for audit trails.
    """
    email = serializers.CharField(source='user.email', read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    deleted_at = serializers.DateTimeField(read_only=True)
    
    # Calculate how long ago it was deleted
    days_since_deletion = serializers.SerializerMethodField()

    class Meta:
        model = AdminRole
        fields = [
            'id',
            'email',
            'username',
            'role_name',
            'permissions',
            'created_at',
            'deleted_at',
            'days_since_deletion',
        ]

    def get_days_since_deletion(self, obj):
        """Calculate days since deletion"""
        if obj.deleted_at:
            from django.utils import timezone
            delta = timezone.now() - obj.deleted_at
            return delta.days
        return None


# ─────────────────────────────────────────────────────────────────────────────
# FOOTER SERIALIZERS
# ─────────────────────────────────────────────────────────────────────────────

class FooterLinkSerializer(serializers.ModelSerializer):
    class Meta:
        model = FooterLink
        fields = [
            'id', 'title', 'url', 'link_type', 'open_new_tab',
            'display_order', 'active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']


class FooterSectionSerializer(serializers.ModelSerializer):
    links = FooterLinkSerializer(many=True, read_only=True)
    link_count = serializers.SerializerMethodField()

    class Meta:
        model = FooterSection
        fields = [
            'id', 'title', 'display_order', 'active',
            'links', 'link_count', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']

    def get_link_count(self, obj):
        return obj.links.filter(active=True).count()


class FooterSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = FooterSettings
        fields = [
            'id', 'copyright_text', 'tagline',
            'show_copyright', 'show_tagline', 'updated_at'
        ]
        read_only_fields = ['id', 'updated_at']


# Public serializer (for frontend footer display)
class PublicFooterSerializer(serializers.Serializer):
    """
    Complete footer data for public display
    """
    sections = FooterSectionSerializer(many=True)
    settings = FooterSettingsSerializer()

# Add after FooterSettingsSerializer

# ─────────────────────────────────────────────────────────────────────────────
# PROMO CODE SERIALIZERS
# ─────────────────────────────────────────────────────────────────────────────

class PromoCodeUsageSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    plan_name = serializers.CharField(source='plan.name', read_only=True)

    class Meta:
        model = PromoCodeUsage
        fields = ['id', 'user', 'username', 'user_email', 'plan_name', 'used_at']
        read_only_fields = ['id', 'used_at']


class PromoCodeSerializer(serializers.ModelSerializer):
    plan_name = serializers.CharField(source='plan.name', read_only=True)
    plan_price = serializers.DecimalField(
        source='plan.price', 
        max_digits=10, 
        decimal_places=2, 
        read_only=True
    )
    is_valid = serializers.BooleanField(read_only=True)
    remaining_uses = serializers.IntegerField(read_only=True)
    usage_percentage = serializers.IntegerField(read_only=True)
    created_by_username = serializers.CharField(
        source='created_by.username', 
        read_only=True, 
        allow_null=True
    )
    recent_usages = serializers.SerializerMethodField()

    class Meta:
        model = PromoCode
        fields = [
            'id', 'code', 'description', 'discount_percentage',
            'plan', 'plan_name', 'plan_price',
            'max_uses', 'current_uses', 'remaining_uses', 'usage_percentage',
            'valid_from', 'valid_until', 'active', 'is_valid',
            'created_by', 'created_by_username', 'created_at', 'updated_at',
            'recent_usages'
        ]
        read_only_fields = ['id', 'current_uses', 'created_by', 'created_at', 'updated_at']

    def get_recent_usages(self, obj):
        # Return last 10 usages
        recent = obj.usages.all()[:10]
        return PromoCodeUsageSerializer(recent, many=True).data

    def validate_code(self, value):
        # Ensure code is uppercase and alphanumeric
        value = value.upper().strip()
        if not value.replace('_', '').replace('-', '').isalnum():
            raise serializers.ValidationError(
                "Code must contain only letters, numbers, hyphens, and underscores"
            )
        return value

    def validate_discount_percentage(self, value):
        if not (0 <= value <= 100):
            raise serializers.ValidationError("Discount must be between 0 and 100")
        return value

    def validate_max_uses(self, value):
        if value < 1:
            raise serializers.ValidationError("Max uses must be at least 1")
        return value

    def validate(self, attrs):
        # Validate valid_until is after valid_from
        if attrs.get('valid_until') and attrs.get('valid_from'):
            if attrs['valid_until'] <= attrs['valid_from']:
                raise serializers.ValidationError({
                    'valid_until': 'Expiration date must be after start date'
                })
        
        return attrs