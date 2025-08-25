from rest_framework.permissions import BasePermission

class IsNotDeletedUser(BasePermission):
    """
    Allows access only to users who are not marked as deleted.
    Assumes the user model has an 'is_deleted' boolean field.
    """
    def has_permission(self, request, view):
        user = getattr(request, 'user', None)
        return bool(user and user.is_authenticated and not getattr(user, 'is_deleted', False))
