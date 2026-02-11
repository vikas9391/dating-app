from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class UserProfile(models.Model):
    # Link to Django User (One-to-One relationship)
    user = models.OneToOneField(
        User, 
        on_delete=models.CASCADE, 
        related_name='profile',
        primary_key=True
    )
    
    # Step 1: Basic Info
    first_name = models.CharField(max_length=100, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    # Gender choices: "Man" or "Woman" only
    gender = models.CharField(max_length=50, blank=True)
    show_gender = models.BooleanField(default=True)
    # Interested In choices: "Men", "Women", or "Everyone"
    interested_in = models.JSONField(default=list, blank=True)
    
    # Step 2: Relationship Status
    relationship_type = models.CharField(max_length=50, blank=True)
    
    # Step 3: Distance
    distance = models.IntegerField(default=25)
    strict_distance = models.BooleanField(default=False)
    
    # Step 4: Lifestyle
    drinking = models.CharField(max_length=50, blank=True)
    smoking = models.CharField(max_length=50, blank=True)
    workout = models.CharField(max_length=50, blank=True)
    pets = models.CharField(max_length=50, blank=True)
    
    # Step 5: Communication
    communication_style = models.JSONField(default=list, blank=True)
    response_pace = models.CharField(max_length=100, blank=True)
    
    # Step 6: Interests
    interests = models.JSONField(default=list, blank=True)
    
    # Step 7: Location
    location = models.CharField(max_length=200, blank=True)
    use_current_location = models.BooleanField(default=False)
    
    # Step 8: Photos
    photos = models.JSONField(default=list, blank=True)
    
    # Step 9: Bio
    bio = models.TextField(max_length=500, blank=True)
    conversation_starter = models.CharField(max_length=300, blank=True)
    
    # Step 10: Social Accounts
    social_accounts = models.JSONField(default=dict, blank=True)
    
    # ===== ADMIN PANEL FIELDS =====
    STATUS_CHOICES = [
        ('online', 'Online'),
        ('away', 'Away'),
        ('offline', 'Offline'),
    ]
    
    ACCOUNT_STATUS_CHOICES = [
        ('active', 'Active'),
        ('suspended', 'Suspended'),
        ('banned', 'Banned'),
        ('pending', 'Pending'),
    ]
    
    phone = models.CharField(max_length=20, blank=True)
    age = models.IntegerField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='offline')
    account_status = models.CharField(max_length=20, choices=ACCOUNT_STATUS_CHOICES, default='active')
    join_date = models.DateTimeField(auto_now_add=True)
    last_active = models.DateTimeField(default=timezone.now)
    active_time = models.IntegerField(default=0)  # in hours
    matches = models.IntegerField(default=0)
    messages = models.IntegerField(default=0)
    photo_count = models.IntegerField(default=0)  # renamed from 'photos' to avoid conflict
    reports = models.IntegerField(default=0)
    profile_complete = models.BooleanField(default=False)
    verified = models.BooleanField(default=False)
    premium = models.BooleanField(default=False)
    # ===== END ADMIN PANEL FIELDS =====
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_complete = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'user_profiles'
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'
    
    def __str__(self):
        return f"{self.user.username}'s Profile"
    
    def save(self, *args, **kwargs):
        # Ensure social_accounts is always a dict, not None
        if self.social_accounts is None:
            self.social_accounts = {}
        
        # Calculate age from date_of_birth
        if self.date_of_birth:
            from datetime import date
            today = date.today()
            self.age = today.year - self.date_of_birth.year - (
                (today.month, today.day) < (self.date_of_birth.month, self.date_of_birth.day)
            )
        
        # Update photo_count based on photos list
        if isinstance(self.photos, list):
            self.photo_count = len(self.photos)
        
        # Auto-check if profile is complete
        self.is_complete = all([
            self.first_name,
            self.date_of_birth,
            self.gender,
            self.location,
            len(self.photos) > 0 if isinstance(self.photos, list) else False
        ])
        
        # Sync profile_complete with is_complete
        self.profile_complete = self.is_complete
        
        super().save(*args, **kwargs)