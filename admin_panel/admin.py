from django.contrib import admin
from .models import  UserReport, AdminAction

@admin.register(UserReport)
class UserReportAdmin(admin.ModelAdmin):
    list_display = ['reporter', 'reported_user', 'reason', 'status', 'created_at']
    list_filter = ['status', 'reason', 'created_at']
    search_fields = ['reporter__username', 'reported_user__username']
    readonly_fields = ['created_at', 'reviewed_at']

@admin.register(AdminAction)
class AdminActionAdmin(admin.ModelAdmin):
    list_display = ['admin', 'target_user', 'action_type', 'created_at']
    list_filter = ['action_type', 'created_at']
    search_fields = ['admin__username', 'target_user__username']
    readonly_fields = ['created_at']