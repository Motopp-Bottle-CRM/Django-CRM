# common/decorators.py
from functools import wraps
from common.models import Profile
from django.http import JsonResponse

def role_required(module_name):

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(self, request, *args, **kwargs):
            #profile = getattr(request.user, "profile", None)
            profile = Profile.objects.filter(user=request.user).first()
            if not profile or not profile.has_access(module_name):
                return JsonResponse(
                    {"error": True, "errors": " - Role-based access. Permission Denied"},
                    status=403
                )
            return view_func(self, request, *args, **kwargs)
        return _wrapped_view
    return decorator

