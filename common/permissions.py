from common.models import Profile
# from tkinter import FALSE
from rest_framework.permissions import BasePermission
class IsNotDeletedUser(BasePermission):
    """
    Allows access only to not deleted users.
    """

    def has_permission(self, request, view):
        return bool(request.user and not request.user.is_deleted)
    
def IsInRoles(module_name):
    class _RolePermission(BasePermission):
        def has_permission(self, request, view):
            profile = Profile.objects.filter(user=request.user).first()
            return bool(request.user and profile and profile.has_access(module_name))
    return _RolePermission
