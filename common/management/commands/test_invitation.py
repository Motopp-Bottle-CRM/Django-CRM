from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from common.models import Profile, UserInvitation, Org
from common.tasks import send_user_invitation_email

User = get_user_model()

class Command(BaseCommand):
    help = 'Test the user invitation system'

    def add_arguments(self, parser):
        parser.add_argument(
            '--email',
            type=str,
            help='Email address for the test invitation',
        )
        parser.add_argument(
            '--org',
            type=str,
            help='Organization name (will create if not exists)',
            default='Test Organization'
        )

    def handle(self, *args, **options):
        email = options['email']
        org_name = options['org']
        
        if not email:
            self.stdout.write(
                self.style.ERROR('Please provide an email address with --email')
            )
            return
        
        # Get or create organization
        org, created = Org.objects.get_or_create(name=org_name)
        if created:
            self.stdout.write(
                self.style.SUCCESS(f'Created organization: {org_name}')
            )
        
        # Check if user already exists
        user, user_created = User.objects.get_or_create(
            email=email,
            defaults={'is_active': False}
        )
        
        if user_created:
            self.stdout.write(
                self.style.SUCCESS(f'Created user: {email}')
            )
        else:
            self.stdout.write(
                self.style.WARNING(f'User already exists: {email}')
            )
        
        # Check if profile exists
        try:
            profile = Profile.objects.get(user=user, org=org)
            self.stdout.write(
                self.style.WARNING(f'Profile already exists for user in organization')
            )
        except Profile.DoesNotExist:
            # Create profile
            profile = Profile.objects.create(
                user=user,
                org=org,
                role='USER',
                is_active=False
            )
            self.stdout.write(
                self.style.SUCCESS(f'Created profile for user in organization')
            )
        
        # Check if invitation exists
        invitation, invitation_created = UserInvitation.objects.get_or_create(
            email=email,
            org=org,
            defaults={
                'invited_by': profile,  # Use the profile as invited_by for testing
                'role': 'USER'
            }
        )
        
        if invitation_created:
            self.stdout.write(
                self.style.SUCCESS(f'Created invitation for: {email}')
            )
        else:
            self.stdout.write(
                self.style.WARNING(f'Invitation already exists for: {email}')
            )
        
        # Send invitation email
        try:
            send_user_invitation_email.delay(invitation.id)
            self.stdout.write(
                self.style.SUCCESS(f'Invitation email sent to: {email}')
            )
            self.stdout.write(
                self.style.SUCCESS(f'Invitation URL: /auth/set-password/{invitation.token}/')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Failed to send invitation email: {str(e)}')
            )
        
        self.stdout.write(
            self.style.SUCCESS('Test invitation setup completed!')
        )
