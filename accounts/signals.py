from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.conf import settings

User = get_user_model()

@receiver(post_save, sender=User)
def send_invitation_email(sender, instance, created, **kwargs):
    if created and instance.email:
        # Generate your invitation link here (customize as needed)
        invitation_link = f"http://localhost:3000/invite/{instance.pk}/"
        send_mail(
            'Your Invitation',
            f'Click here to join: {invitation_link}',
            settings.DEFAULT_FROM_EMAIL if hasattr(settings, 'DEFAULT_FROM_EMAIL') else 'from@example.com',
            [instance.email],
            fail_silently=False,
        )
