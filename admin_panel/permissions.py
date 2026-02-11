# permissions.py
from rest_framework.permissions import BasePermission
from .models import AdminRole
    
class IsAdminUser(BasePermission):
    """
    Allows access only to users with is_staff=True AND an active AdminRole.
    Django superusers always pass.
    """

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        if request.user.is_superuser:
            return True

        if not request.user.is_staff:
            return False

        try:
            role = request.user.admin_role
            return role.is_active
        except AdminRole.DoesNotExist:
            return False


class HasSectionPermission(BasePermission):
    """
    Granular permission that checks whether the requesting admin has
    at least *required_level* access to a specific *section_id*.

    Usage — set class attributes on your view:

        class MyView(APIView):
            permission_classes = [HasSectionPermission]
            section_id = 'users'
            required_level = 'edit'   # defaults to 'view'

    Super-admins and Django superusers bypass the check entirely.
    """

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        if request.user.is_superuser:
            return True

        if not request.user.is_staff:
            return False

        section_id = getattr(view, 'section_id', None)
        if section_id is None:
            return False

        required_level = getattr(view, 'required_level', 'view')

        try:
            role = request.user.admin_role
        except AdminRole.DoesNotExist:
            return False

        if not role.is_active:
            return False

        return role.has_access(section_id, required_level)


class IsSuperAdmin(BasePermission):
    """
    Only Django superusers OR AdminRoles with is_super_admin=True.
    Used to protect the admin-role management endpoints themselves.
    """

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        if request.user.is_superuser:
            return True

        try:
            role = request.user.admin_role
            return role.is_active and role.is_super_admin
        except AdminRole.DoesNotExist:
            return False