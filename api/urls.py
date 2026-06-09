from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import AuthViewSet, UserViewSet, AuditLogViewSet, health_check, create_staff

router = DefaultRouter()
router.register(r'auth', AuthViewSet, basename='auth')
router.register(r'users', UserViewSet, basename='users')
router.register(r'audit-logs', AuditLogViewSet, basename='audit-logs')

urlpatterns = [
    path('health/', health_check, name='health'),
    path('admin/staff/', create_staff, name='create-staff'),
    path('', include(router.urls)),
]
