from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from django.conf import settings
from .models import Profile, UserInvitation
from .tasks import send_user_invitation_email
from .models import generate_invitation_token



@receiver(post_save, sender=UserInvitation)
def update_user_status_on_invitation_acceptance(sender, instance, created, **kwargs):
    """Update user and profile status when invitation is accepted"""
    if not created and instance.is_accepted:
        try:
            # Get the user and profile
            from django.contrib.auth import get_user_model
            User = get_user_model()
            
            user = User.objects.get(email=instance.email)
            profile = Profile.objects.get(user=user, org=instance.org)
            
            # Activate both user and profile
            user.is_active = True
            user.save()
            
            profile.is_active = True
            profile.save()
            
        except (User.DoesNotExist, Profile.DoesNotExist):
            # User or profile doesn't exist, skip
            pass
