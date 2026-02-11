# ============================================
# profiles/urls.py
# ============================================
from django.urls import path
from . import views

app_name = 'profile'

urlpatterns = [
    # Get authenticated user's profile
    path('', views.get_profile, name='get_profile'),
    
    # Create or update profile
    path('save/', views.create_or_update_profile, name='save_profile'),
    
    # Delete profile
    path('delete/', views.delete_profile, name='delete_profile'),
    
    # Check profile status
    path('status/', views.profile_status, name='profile_status'),
    
    # Upload photo
    path('upload-photo/', views.upload_photo, name='upload_photo'),
]