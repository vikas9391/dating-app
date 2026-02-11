from django.conf import settings 
from admin_panel.models import PremiumPlan
from django.db import models


class Like(models.Model):
    from_email = models.EmailField()
    to_email = models.EmailField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("from_email", "to_email")


class Chat(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    last_message = models.TextField(null=True, blank=True)
    last_message_at = models.DateTimeField(null=True, blank=True)


class ChatParticipant(models.Model):
    chat = models.ForeignKey(Chat, on_delete=models.CASCADE)
    email = models.EmailField()

    class Meta:
        unique_together = ("chat", "email")


class Message(models.Model):
    chat = models.ForeignKey(Chat, on_delete=models.CASCADE)
    sender = models.EmailField()
    receiver = models.EmailField()
    content = models.TextField()
    type = models.CharField(max_length=20, default="text")
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)
    read_at = models.DateTimeField(null=True, blank=True)


class Match(models.Model):
    user_a = models.EmailField()
    user_b = models.EmailField()
    chat = models.ForeignKey(Chat, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, default="active")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("user_a", "user_b")


class BlockedUser(models.Model):
    blocker = models.EmailField(db_index=True)
    blocked = models.EmailField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("blocker", "blocked")


class Payment(models.Model):
    """
    Model to track premium plan purchases and payments.
    
    ✅ UPDATED: Now includes promo_code tracking for discount transparency
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    plan = models.ForeignKey(PremiumPlan, on_delete=models.PROTECT)
    
    # ✅ NEW: Track which promo code was used (if any)
    promo_code = models.ForeignKey(
        'admin_panel.PromoCode',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='payments',
        help_text="Promo code used for this payment (if any)"
    )
    
    # Razorpay payment tracking
    razorpay_order_id = models.CharField(max_length=100)
    razorpay_payment_id = models.CharField(max_length=100)
    
    # ✅ NEW: Track original price before discount
    original_amount = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Original plan price before any discounts"
    )
    
    # ✅ NEW: Track discount amount
    discount_amount = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Total discount applied (from promo code)"
    )
    
    # Final amount paid
    amount = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        help_text="Final amount paid after discounts"
    )
    
    # Payment status
    status = models.CharField(max_length=20)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        promo_info = f" (with {self.promo_code.code})" if self.promo_code else ""
        return f"{self.user.username} - {self.plan.name}{promo_info} - ₹{self.amount}"


class Notification(models.Model):
    user = models.EmailField()  # receiver
    type = models.CharField(max_length=50)
    match = models.ForeignKey(
        Match,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )
    chat_id = models.IntegerField(null=True, blank=True)

    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]