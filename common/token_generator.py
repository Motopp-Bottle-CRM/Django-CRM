# from django.utils import six
import six
from django.contrib.auth.tokens import PasswordResetTokenGenerator


class TokenGenerator(PasswordResetTokenGenerator):
    """this class is used to generate a unique token to identify the user"""

    def _make_hash_value(self, user, timestamp):
        return (
            six.text_type(user.pk)
            + six.text_type(timestamp)
            + six.text_type(user.is_active)
        )


account_activation_token = TokenGenerator()



def send_invitation_email(user, request):
    token = default_token_generator.make_token(user)
    uuid = urlsafe_base64_encode(force_bytes(user.pk))

    # React frontend route
    frontend_url = f"http://localhost:3000/set-password/{uuid}/{token}/"

    subject = "You are invited to Bottle CRM application"
    message = f"Hi {user.username},\n\nClick the link below to set your password:\n{frontend_url}"

    send_mail(subject, message, "noreply@bottlecrm.com", [user.email])