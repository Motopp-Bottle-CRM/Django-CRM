from django.core.management.base import BaseCommand
from common.models import Profile, User


class Command(BaseCommand):
    help = 'Reactivate an admin user account in case of lockout'

    def add_arguments(self, parser):
        parser.add_argument('email', type=str, help='Email of the admin user to reactivate')
        parser.add_argument('--force', action='store_true', help='Force reactivation even if already active')

    def handle(self, *args, **options):
        email = options['email']
        force = options['force']
        
        try:
            user = User.objects.get(email=email)
            profile = Profile.objects.get(user=user)
            
            if profile.is_active and not force:
                self.stdout.write(
                    self.style.WARNING(f'User {email} is already active. Use --force to reactivate anyway.')
                )
                return
            
            profile.is_active = True
            profile.save()
            
            self.stdout.write(
                self.style.SUCCESS(f'Successfully reactivated admin user: {email}')
            )
            self.stdout.write(f'Profile ID: {profile.id}')
            self.stdout.write(f'Role: {profile.role}')
            self.stdout.write(f'Organization: {profile.org}')
            
        except User.DoesNotExist:
            self.stdout.write(
                self.style.ERROR(f'User with email {email} not found')
            )
        except Profile.DoesNotExist:
            self.stdout.write(
                self.style.ERROR(f'Profile for user {email} not found')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error reactivating user: {str(e)}')
            )
