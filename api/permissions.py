from rest_framework.permissions import BasePermission


class IsAdmin(BasePermission):
    """Allow access only to authenticated users whose role is 'admin'."""
    message = 'Administrator role required.'

    def has_permission(self, request, view):
        user = getattr(request, 'user', None)
        return bool(user and user.is_authenticated and getattr(user, 'role', None) == 'admin')


class IsAdminOrStaff(BasePermission):
    """Admin or front-desk clerk ('staff'/'receptionist') — used for account provisioning
    so the receptionist can register doctors / patients (DoctorRegistrationClerk)."""
    message = 'Administrator or staff role required.'

    def has_permission(self, request, view):
        user = getattr(request, 'user', None)
        return bool(
            user and user.is_authenticated
            and getattr(user, 'role', None) in ('admin', 'staff', 'receptionist')
        )
