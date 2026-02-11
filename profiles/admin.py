# ============================================
# profiles/admin.py
# ============================================
from django.contrib import admin
from .models import UserProfile

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = [
        'user', 
        'first_name', 
        'gender', 
        'location', 
        'is_complete',
        'created_at'
    ]
    list_filter = ['is_complete', 'gender', 'created_at']
    search_fields = ['user__username', 'user__email', 'first_name', 'location']
    readonly_fields = ['created_at', 'updated_at', 'is_complete']
    
    fieldsets = (
        ('User', {
            'fields': ('user',)
        }),
        ('Basic Information', {
            'fields': (
                'first_name', 
                'date_of_birth', 
                'gender', 
                'show_gender',
                'interested_in'
            )
        }),
        ('Preferences', {
            'fields': (
                'orientation',
                'show_orientation',
                'relationship_type',
                'distance',
                'strict_distance'
            )
        }),
        ('Lifestyle', {
            'fields': ('drinking', 'smoking', 'workout', 'pets')
        }),
        ('Communication', {
            'fields': ('communication_style', 'response_pace')
        }),
        ('Interests & Location', {
            'fields': ('interests', 'location', 'use_current_location')
        }),
        ('Media & Bio', {
            'fields': ('photos', 'bio', 'conversation_starter')
        }),
        ('Metadata', {
            'fields': ('is_complete', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


