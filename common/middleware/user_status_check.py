from django.http import JsonResponse
from django.contrib.auth import get_user_model
from common.models import Profile
import json

User = get_user_model()

class UserStatusCheckMiddleware:
    """
    Middleware to check if the authenticated user is still active.
    If user is deactivated, immediately return 401 Unauthorized.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip check for login and auth endpoints
        if request.path.startswith('/api/auth/') or request.path.startswith('/api/set-password/'):
            response = self.get_response(request)
            return response
            
        # Check if user is authenticated
        if hasattr(request, 'user') and request.user.is_authenticated:
            try:
                # Check if user is still active
                if not request.user.is_active:
                    return JsonResponse({
                        'error': True,
                        'message': 'Your account has been deactivated. Please contact your administrator.',
                        'code': 'USER_DEACTIVATED'
                    }, status=401)
                
                # Check if user has an active profile
                profile = Profile.objects.filter(user=request.user, is_active=True).first()
                if not profile:
                    return JsonResponse({
                        'error': True,
                        'message': 'Your account has been deactivated. Please contact your administrator.',
                        'code': 'USER_DEACTIVATED'
                    }, status=401)
                    
            except Exception as e:
                # If there's an error checking user status, log it but don't block the request
                print(f"Error checking user status: {e}")
                pass

        response = self.get_response(request)
        return response
