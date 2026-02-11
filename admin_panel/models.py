from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from decimal import Decimal
# Ensure you have the 'profiles' app. If not, comment this import out.
from profiles.models import UserProfile 
import uuid


# ─────────────────────────────────────────────────────────────────────────────
# REVIEW
# ─────────────────────────────────────────────────────────────────────────────

class Review(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reviews')
    rating = models.IntegerField(choices=[(i, i) for i in range(1, 6)])
    text = models.TextField(max_length=500)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    reviewed_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='reviewed_reviews'
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    admin_notes = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username} - {self.rating} stars - {self.status}"


# ─────────────────────────────────────────────────────────────────────────────
# PREMIUM
# ─────────────────────────────────────────────────────────────────────────────

class PremiumPlan(models.Model):
    PLAN_TYPES = [
        ('monthly', 'Monthly'),
        ('quarterly', 'Quarterly'),
        ('biannual', '6 Months'),
        ('annual', 'Annual'),
    ]

    ICON_CHOICES = [
        ('zap', 'Zap'),
        ('flame', 'Flame'),
        ('trending-up', 'Trending Up'),
        ('crown', 'Crown'),
        ('star', 'Star'),
    ]

    plan_id = models.CharField(max_length=50, unique=True, primary_key=True)
    name = models.CharField(max_length=100)
    duration = models.CharField(max_length=50)
    plan_type = models.CharField(max_length=20, choices=PLAN_TYPES)

    price = models.DecimalField(max_digits=10, decimal_places=2)
    original_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    # Allow blank so model can calculate it
    price_per_month = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    discount_text = models.CharField(max_length=50, null=True, blank=True)

    icon = models.CharField(max_length=20, choices=ICON_CHOICES, default='zap')
    color = models.CharField(max_length=100, default='from-blue-500 to-cyan-500')
    gradient = models.CharField(max_length=100, default='bg-gradient-to-br from-blue-500 to-cyan-500')
    popular = models.BooleanField(default=False)

    features = models.JSONField(default=list)

    active = models.BooleanField(default=True)
    display_order = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['display_order', 'price']
        verbose_name = 'Premium Plan'
        verbose_name_plural = 'Premium Plans'

    def __str__(self):
        return f"{self.name} - ${self.price}"

    def save(self, *args, **kwargs):
        if self.price_per_month is None:
            months_map = {'monthly': 1, 'quarterly': 3, 'biannual': 6, 'annual': 12}
            months = months_map.get(self.plan_type, 1)
            self.price_per_month = float(self.price) / months

        if self.original_price and float(self.original_price) > float(self.price):
            discount_percent = ((float(self.original_price) - float(self.price)) / float(self.original_price)) * 100
            self.discount_text = f"Save {int(discount_percent)}%"

        super().save(*args, **kwargs)


class PremiumFeature(models.Model):
    ICON_CHOICES = [
        ('eye', 'Eye'), ('zap', 'Zap'), ('message-circle', 'Message Circle'),
        ('map-pin', 'Map Pin'), ('shield', 'Shield'), ('star', 'Star'),
        ('heart', 'Heart'), ('crown', 'Crown'),
    ]

    title = models.CharField(max_length=100)
    description = models.TextField()
    icon = models.CharField(max_length=20, choices=ICON_CHOICES, default='star')

    active = models.BooleanField(default=True)
    display_order = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['display_order']
        verbose_name = 'Premium Feature'
        verbose_name_plural = 'Premium Features'

    def __str__(self):
        return self.title


# ─────────────────────────────────────────────────────────────────────────────
# REPORTS & ACTIONS
# ─────────────────────────────────────────────────────────────────────────────

class UserReport(models.Model):
    REPORT_REASONS = [
        ('spam', 'Spam'), ('harassment', 'Harassment'),
        ('inappropriate', 'Inappropriate Content'),
        ('fake', 'Fake Profile'), ('other', 'Other'),
    ]
    STATUS_CHOICES = [
        ('pending', 'Pending'), ('reviewed', 'Reviewed'),
        ('resolved', 'Resolved'), ('dismissed', 'Dismissed'),
    ]

    reporter = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reports_made')
    reported_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reports_received')
    reason = models.CharField(max_length=50, choices=REPORT_REASONS)
    description = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    reviewed_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='reports_reviewed'
    )
    admin_notes = models.TextField(blank=True)

    def __str__(self):
        return f"Report against {self.reported_user.username} by {self.reporter.username}"

    class Meta:
        db_table = 'user_reports'
        ordering = ['-created_at']


class AdminAction(models.Model):
    ACTION_TYPES = [
        ('suspend', 'Suspend'), ('ban', 'Ban'), ('activate', 'Activate'),
        ('delete', 'Delete'), ('verify', 'Verify'), ('warn', 'Warn'),
    ]

    admin = models.ForeignKey(User, on_delete=models.CASCADE, related_name='admin_actions')
    target_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='actions_received')
    action_type = models.CharField(max_length=20, choices=ACTION_TYPES)
    reason = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.action_type} on {self.target_user.username} by {self.admin.username}"

    class Meta:
        db_table = 'admin_actions'
        ordering = ['-created_at']


# ─────────────────────────────────────────────────────────────────────────────
# EXPERT TIPS
# ─────────────────────────────────────────────────────────────────────────────

class ExpertTip(models.Model):
    ICON_CHOICES = [
        ('message-circle', 'Message Circle'), ('target', 'Target'),
        ('sparkles', 'Sparkles'), ('lightbulb', 'Lightbulb'),
        ('heart', 'Heart'), ('star', 'Star'), ('zap', 'Zap'),
        ('users', 'Users'), ('trending-up', 'Trending Up'),
    ]
    COLOR_CHOICES = [
        ('text-blue-500', 'Blue'), ('text-rose-500', 'Rose'),
        ('text-amber-500', 'Amber'), ('text-violet-500', 'Violet'),
        ('text-green-500', 'Green'), ('text-purple-500', 'Purple'),
        ('text-pink-500', 'Pink'), ('text-teal-500', 'Teal'),
    ]
    BG_CHOICES = [
        ('bg-blue-50', 'Blue'), ('bg-rose-50', 'Rose'),
        ('bg-amber-50', 'Amber'), ('bg-violet-50', 'Violet'),
        ('bg-green-50', 'Green'), ('bg-purple-50', 'Purple'),
        ('bg-pink-50', 'Pink'), ('bg-teal-50', 'Teal'),
    ]

    name = models.CharField(max_length=100)
    role = models.CharField(max_length=100)
    image = models.URLField(max_length=500)
    tip = models.TextField()

    icon = models.CharField(max_length=20, choices=ICON_CHOICES, default='lightbulb')
    icon_color = models.CharField(max_length=20, choices=COLOR_CHOICES, default='text-blue-500')
    bg_color = models.CharField(max_length=20, choices=BG_CHOICES, default='bg-blue-50')

    active = models.BooleanField(default=True)
    display_order = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['display_order', '-created_at']
        verbose_name = 'Expert Tip'
        verbose_name_plural = 'Expert Tips'

    def __str__(self):
        return f"{self.name} - {self.role}"


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN ROLE MANAGEMENT - WITH SOFT DELETE IMPLEMENTATION
# ─────────────────────────────────────────────────────────────────────────────

VALID_SECTIONS = {
    'overview', 'users', 'reports', 'analytics',
    'premium', 'expert-tips', 'reviews','footer',
    'promo-codes',
}
VALID_LEVELS = {'none', 'view', 'edit'}


def _default_permissions():
    return {s: 'none' for s in VALID_SECTIONS}


def _generate_invite_token():
    return uuid.uuid4().hex


class AdminRole(models.Model):
    """
    Model to manage admin roles and permissions with SOFT DELETE support.
    
    Soft delete keeps the record in the database but marks it as inactive,
    allowing for audit trails and data recovery.
    
    * is_super_admin=True → full edit everywhere, cannot be modified by others.
    * permissions is a flat JSON map: { section_id: "none"|"view"|"edit" }
    * invite_token is generated on creation and cleared once the user accepts.
    """

    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name='admin_role',
    )
    role_name = models.CharField(max_length=100)
    is_super_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    permissions = models.JSONField(default=_default_permissions)

    invite_token = models.CharField(
        max_length=64, unique=True, null=True, blank=True,
        default=_generate_invite_token,
    )
    invite_accepted = models.BooleanField(default=False)
    
    # Password tracking fields
    initial_password = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text="Temporary password generated on account creation"
    )
    password_changed = models.BooleanField(
        default=False,
        help_text="True if admin has changed their password from the initial one"
    )
    
    # ✅ NEW: Soft delete tracking
    deleted_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when the admin was soft-deleted"
    )

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'admin_roles'
        ordering = ['-created_at']
        verbose_name = 'Admin Role'
        verbose_name_plural = 'Admin Roles'
        indexes = [
            models.Index(fields=['is_active']),
            models.Index(fields=['deleted_at']),
            models.Index(fields=['user', 'is_active']),
        ]

    def __str__(self):
        label = 'Super Admin' if self.is_super_admin else self.role_name
        status = "DELETED" if self.deleted_at else ("INACTIVE" if not self.is_active else "ACTIVE")
        return f"{self.user.username} ({label}) [{status}]"

    # ── Properties ───────────────────────────────────────────────────────

    @property
    def is_deleted(self):
        """Check if this admin role has been soft-deleted"""
        return self.deleted_at is not None

    @property
    def days_since_deletion(self):
        """Calculate days since deletion (useful for cleanup policies)"""
        if self.deleted_at:
            delta = timezone.now() - self.deleted_at
            return delta.days
        return None

    # ── Permission Helpers ───────────────────────────────────────────────

    def get_permission(self, section_id: str) -> str:
        if self.is_super_admin:
            return 'edit'
        return self.permissions.get(section_id, 'none')

    def has_access(self, section_id: str, required_level: str = 'view') -> bool:
        RANK = {'none': 0, 'view': 1, 'edit': 2}
        return RANK.get(self.get_permission(section_id), 0) >= RANK.get(required_level, 0)

    # ── Soft Delete Methods ──────────────────────────────────────────────

    def soft_delete(self):
        """
        ✅ Soft delete this admin role.
        
        Marks both the AdminRole and associated User as inactive.
        """
        self.is_active = False
        self.deleted_at = timezone.now()
        self.save(update_fields=['is_active', 'deleted_at'])
        
        # Also deactivate the user
        if self.user:
            self.user.is_active = False
            self.user.save(update_fields=['is_active'])

    def restore(self):
        """
        ✅ Restore a soft-deleted admin role.
        
        Reactivates both the AdminRole and associated User.
        """
        self.is_active = True
        self.deleted_at = None
        self.save(update_fields=['is_active', 'deleted_at'])
        
        # Also reactivate the user
        if self.user:
            self.user.is_active = True
            self.user.save(update_fields=['is_active'])

    def permanent_delete(self):
        """
        ✅ Permanently delete this admin role and associated user.
        
        This is a hard delete that cannot be undone.
        Use only when necessary (e.g., GDPR compliance).
        """
        user = self.user
        self.delete()
        if user:
            user.delete()

    # ── Utility Methods ──────────────────────────────────────────────────

    def update_last_login(self):
        """Update the last login timestamp"""
        self.last_login = timezone.now()
        self.save(update_fields=['last_login'])

    def mark_password_changed(self):
        """
        Mark that the admin has changed their password.
        This should be called when the admin successfully changes their password.
        """
        self.password_changed = True
        self.initial_password = None  # Clear the stored password for security
        self.save(update_fields=['password_changed', 'initial_password'])

    # ── Class Methods ────────────────────────────────────────────────────

    @classmethod
    def get_active_admins(cls):
        """Get all active (non-deleted) admin roles"""
        return cls.objects.filter(is_active=True, deleted_at__isnull=True)

    @classmethod
    def get_deleted_admins(cls):
        """Get all soft-deleted admin roles"""
        return cls.objects.filter(deleted_at__isnull=False)

    @classmethod
    def cleanup_old_deleted(cls, days=30):
        """
        ✅ Permanently delete admin roles that have been soft-deleted
        for more than the specified number of days.
        
        Args:
            days: Number of days after which to permanently delete
            
        Returns:
            Number of admins permanently deleted
        """
        from datetime import timedelta
        cutoff_date = timezone.now() - timedelta(days=days)
        old_deleted = cls.objects.filter(
            deleted_at__lt=cutoff_date
        )
        
        count = old_deleted.count()
        for admin in old_deleted:
            admin.permanent_delete()
        
        return count

    # ── Validation ───────────────────────────────────────────────────────

    def clean(self):
        from django.core.exceptions import ValidationError
        if not isinstance(self.permissions, dict):
            raise ValidationError('permissions must be a JSON object.')
        for key, value in self.permissions.items():
            if key not in VALID_SECTIONS:
                raise ValidationError(f'Unknown section: "{key}".')
            if value not in VALID_LEVELS:
                raise ValidationError(f'Invalid level "{value}" for "{key}".')

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

# ─────────────────────────────────────────────────────────────────────────────
# FOOTER MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

class FooterSection(models.Model):
    """
    Footer column/section (e.g., Company, Support, Legal, Social)
    """
    title = models.CharField(max_length=100)
    display_order = models.IntegerField(default=0)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'footer_sections'
        ordering = ['display_order', 'title']
        verbose_name = 'Footer Section'
        verbose_name_plural = 'Footer Sections'

    def __str__(self):
        return self.title


class FooterLink(models.Model):
    """
    Individual link within a footer section
    """
    LINK_TYPES = [
        ('internal', 'Internal Link'),
        ('external', 'External Link'),
    ]

    section = models.ForeignKey(
        FooterSection, 
        on_delete=models.CASCADE, 
        related_name='links'
    )
    title = models.CharField(max_length=100)
    url = models.CharField(max_length=500)
    link_type = models.CharField(max_length=20, choices=LINK_TYPES, default='internal')
    open_new_tab = models.BooleanField(
        default=False,
        help_text="Open link in new tab (for external links)"
    )
    display_order = models.IntegerField(default=0)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'footer_links'
        ordering = ['section', 'display_order', 'title']
        verbose_name = 'Footer Link'
        verbose_name_plural = 'Footer Links'

    def __str__(self):
        return f"{self.section.title} - {self.title}"


class FooterSettings(models.Model):
    """
    Global footer settings (copyright text, tagline, etc.)
    Singleton model - only one instance should exist
    """
    copyright_text = models.CharField(
        max_length=200,
        default="© 2026 The Dating App. All rights reserved."
    )
    tagline = models.CharField(
        max_length=200,
        default="Made in Hyderabad, India ❤️ for genuine connections."
    )
    show_copyright = models.BooleanField(default=True)
    show_tagline = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'footer_settings'
        verbose_name = 'Footer Settings'
        verbose_name_plural = 'Footer Settings'

    def __str__(self):
        return "Footer Settings"

    def save(self, *args, **kwargs):
        # Ensure only one instance exists (singleton)
        self.pk = 1
        super().save(*args, **kwargs)

    @classmethod
    def get_settings(cls):
        """Get or create the singleton instance"""
        obj, created = cls.objects.get_or_create(pk=1)
        return obj


# ─────────────────────────────────────────────────────────────────────────────
# PROMO CODE SYSTEM
# ─────────────────────────────────────────────────────────────────────────────

class PromoCode(models.Model):
    """
    Promotional codes for premium plans
    """
    # Code details
    code = models.CharField(
        max_length=50, 
        unique=True,
        help_text="Unique promo code (e.g., SUMMER2024, FREEMONTH100)"
    )
    description = models.TextField(
        blank=True,
        help_text="Internal description (not shown to users)"
    )
    
    # Plan restriction - ONLY FOR ONE PLAN
    plan = models.ForeignKey(
        PremiumPlan,
        on_delete=models.CASCADE,
        related_name='promo_codes',
        help_text="Which plan this code applies to"
    )
    
    # Make it FREE
    discount_percentage = models.IntegerField(
        default=100,
        help_text="Discount percentage (100 = FREE)"
    )
    
    # Usage limits
    max_uses = models.IntegerField(
        default=100,
        help_text="Maximum number of people who can use this code"
    )
    current_uses = models.IntegerField(
        default=0,
        help_text="Current number of times used"
    )
    
    # Time restrictions
    valid_from = models.DateTimeField(
        default=timezone.now,
        help_text="When this code becomes valid"
    )
    valid_until = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When this code expires (leave empty for no expiration)"
    )
    
    # Status
    active = models.BooleanField(
        default=True,
        help_text="Whether this code is currently active"
    )
    
    # Metadata
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_promo_codes'
    )
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'promo_codes'
        ordering = ['-created_at']
        verbose_name = 'Promo Code'
        verbose_name_plural = 'Promo Codes'
        indexes = [
            models.Index(fields=['code']),
            models.Index(fields=['active']),
        ]

    def __str__(self):
        return f"{self.code} - {self.plan.name} ({self.current_uses}/{self.max_uses})"

    @property
    def is_valid(self):
        """Check if code is currently valid"""
        if not self.active:
            return False
        
        # Check if expired
        if self.valid_until and timezone.now() > self.valid_until:
            return False
        
        # Check if not yet valid
        if timezone.now() < self.valid_from:
            return False
        
        # Check usage limit
        if self.current_uses >= self.max_uses:
            return False
        
        return True

    @property
    def remaining_uses(self):
        """Get remaining uses"""
        return max(0, self.max_uses - self.current_uses)

    @property
    def usage_percentage(self):
        """Get usage as percentage"""
        if self.max_uses == 0:
            return 0
        return int((self.current_uses / self.max_uses) * 100)

    # ✅ CRITICAL FIX: Add these methods to fix the AttributeError
    def apply_discount(self, original_amount):
        """
        Apply the discount to the given amount.
        Returns the final price after discount.
        
        Args:
            original_amount: The original price (can be int, float, or Decimal)
            
        Returns:
            Decimal: The final price after applying discount
        """
        if self.discount_percentage <= 0:
            return Decimal(str(original_amount))
        
        # Convert to Decimal for precision
        original = Decimal(str(original_amount))
        discount_pct = Decimal(str(self.discount_percentage))
        
        # Calculate discount amount
        discount_amount = (original * discount_pct) / Decimal('100')
        
        # Calculate final amount
        final_amount = original - discount_amount
        
        # Ensure we don't return negative amounts
        return max(Decimal('0'), final_amount)
    
    def get_discount_amount(self, original_amount):
        """
        Get the actual discount amount (not the final price).
        
        Args:
            original_amount: The original price
            
        Returns:
            Decimal: The discount amount
        """
        original = Decimal(str(original_amount))
        discount_pct = Decimal(str(self.discount_percentage))
        
        return (original * discount_pct) / Decimal('100')

    def can_be_used_by(self, user):
        """Check if a specific user can use this code"""
        if not self.is_valid:
            return False
        
        # Check if user already used this code
        if PromoCodeUsage.objects.filter(promo_code=self, user=user).exists():
            return False
        
        return True

    def use_code(self, user):
        """
        Mark this code as used by a user
        Returns (success, message)
        """
        if not self.is_valid:
            return False, "This promo code is no longer valid"
        
        if PromoCodeUsage.objects.filter(promo_code=self, user=user).exists():
            return False, "You have already used this promo code"
        
        # Increment usage counter
        self.current_uses += 1
        self.save(update_fields=['current_uses'])
        
        # Create usage record
        PromoCodeUsage.objects.create(
            promo_code=self,
            user=user,
            plan=self.plan
        )
        
        return True, "Promo code applied successfully!"


class PromoCodeUsage(models.Model):
    """
    Track who used which promo codes
    """
    promo_code = models.ForeignKey(
        PromoCode,
        on_delete=models.CASCADE,
        related_name='usages'
    )
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='promo_code_usages'
    )
    plan = models.ForeignKey(
        PremiumPlan,
        on_delete=models.CASCADE
    )
    used_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        db_table = 'promo_code_usages'
        ordering = ['-used_at']
        verbose_name = 'Promo Code Usage'
        verbose_name_plural = 'Promo Code Usages'
        unique_together = [['promo_code', 'user']]  
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['promo_code']),
        ]

    def __str__(self):
        return f"{self.user.username} used {self.promo_code.code} on {self.used_at.strftime('%Y-%m-%d')}"