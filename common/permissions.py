from rest_framework.permissions import BasePermission
class IsNotDeletedUser(BasePermission):
    """
    Allows access only to not deleted users.
    """

    def has_permission(self, request, view):
        return bool(request.user and not request.user.is_deleted)