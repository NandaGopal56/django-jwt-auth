from rest_framework.permissions import BasePermission


# Custom permission for users with "IsAdmin" = True.
class IsAdmin(BasePermission):
    """
    Allows access only to "IsAdmin" users.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_admin