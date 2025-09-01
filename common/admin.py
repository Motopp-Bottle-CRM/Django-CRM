from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone

from common.models import Address, Comment, CommentFiles, User, Profile, UserInvitation
from common.models import generate_invitation_token

# Register your models here.

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'is_active', 'is_staff', 'is_deleted')
    list_filter = ('is_active', 'is_staff', 'is_deleted')
    search_fields = ('email',)
    ordering = ('-is_active',)
    actions = ['create_invitation']
    
    def create_invitation(self, request, queryset):
        """Admin action to create invitations for selected users"""
        from common.models import Profile, UserInvitation
        from common.tasks import send_user_invitation_email
        
        count = 0
        for user in queryset:
            if not user.is_active:
                # Check if user has a profile
                try:
                    profile = Profile.objects.get(user=user)
                    
                    # Check if invitation already exists
                    existing_invitation = UserInvitation.objects.filter(
                        email=user.email,
                        org=profile.org,
                        is_accepted=False
                    ).first()
                    
                    if not existing_invitation:
                        # Create new invitation
                        invitation = UserInvitation.objects.create(
                            email=user.email,
                            invited_by=request.user.profile if hasattr(request.user, 'profile') else None,
                            org=profile.org,
                            role=profile.role,
                        )
                        
                        # Send invitation email
                        send_user_invitation_email.delay(invitation.id)
                        count += 1
                    else:
                        # Update existing invitation
                        existing_invitation.token = generate_invitation_token()
                        existing_invitation.expires_at = timezone.now() + timezone.timedelta(days=7)
                        existing_invitation.save()
                        
                        # Send invitation email
                        send_user_invitation_email.delay(existing_invitation.id)
                        count += 1
                        
                except Profile.DoesNotExist:
                    continue
        
        if count == 1:
            message = "1 invitation was created and sent successfully."
        else:
            message = f"{count} invitations were created and sent successfully."
        
        self.message_user(request, message)
    
    create_invitation.short_description = "Create and send invitations for selected users"

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'org', 'role', 'is_active', 'date_of_joining', 'created_at')
    list_filter = ('is_active', 'role', 'org', 'created_at')
    search_fields = ('user__email', 'org__name')
    readonly_fields = ('created_at', 'updated_at', 'created_by', 'updated_by')
    ordering = ('-created_at',)
    actions = ['activate_users', 'deactivate_users']
    
    def activate_users(self, request, queryset):
        """Admin action to activate selected users"""
        count = queryset.update(is_active=True)
        if count == 1:
            message = "1 user was activated successfully."
        else:
            message = f"{count} users were activated successfully."
        self.message_user(request, message)
    
    activate_users.short_description = "Activate selected users"
    
    def deactivate_users(self, request, queryset):
        """Admin action to deactivate selected users"""
        count = queryset.update(is_active=False)
        if count == 1:
            message = "1 user was deactivated successfully."
        else:
            message = f"{count} users were deactivated successfully."
        self.message_user(request, message)
    
    deactivate_users.short_description = "Deactivate selected users"

@admin.register(UserInvitation)
class UserInvitationAdmin(admin.ModelAdmin):
    list_display = ('email', 'org', 'role', 'invited_by', 'is_accepted', 'expires_at', 'status')
    list_filter = ('is_accepted', 'role', 'org', 'created_at')
    search_fields = ('email', 'org__name', 'invited_by__user__email')
    readonly_fields = ('token', 'created_at', 'updated_at', 'accepted_at', 'created_by', 'updated_by')
    ordering = ('-created_at',)
    actions = ['resend_invitation']
    
    def status(self, obj):
        if obj.is_accepted:
            return format_html('<span style="color: green;">Accepted</span>')
        elif obj.is_expired():
            return format_html('<span style="color: red;">Expired</span>')
        else:
            return format_html('<span style="color: orange;">Pending</span>')
    status.short_description = 'Status'
    
    def resend_invitation(self, request, queryset):
        """Admin action to resend invitations"""
        from common.tasks import send_user_invitation_email
        
        count = 0
        for invitation in queryset:
            if not invitation.is_accepted and not invitation.is_expired():
                # Update token and expiration
                invitation.token = generate_invitation_token()
                invitation.expires_at = timezone.now() + timezone.timedelta(days=7)
                invitation.save()
                
                # Send email
                send_user_invitation_email.delay(invitation.id)
                count += 1
        
        if count == 1:
            message = "1 invitation was resent successfully."
        else:
            message = f"{count} invitations were resent successfully."
        
        self.message_user(request, message)
    
    resend_invitation.short_description = "Resend selected invitations"

@admin.register(Address)
class AddressAdmin(admin.ModelAdmin):
    list_display = ('city', 'state', 'country', 'created_at')
    list_filter = ('country', 'state', 'created_at')
    search_fields = ('city', 'state', 'country')
    readonly_fields = ('created_at', 'updated_at', 'created_by', 'updated_by')
    ordering = ('-created_at',)

@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    list_display = ('comment', 'commented_by', 'commented_on', 'created_at')
    list_filter = ('commented_on', 'created_at')
    search_fields = ('comment', 'commented_by__user__email')
    readonly_fields = ('created_at', 'updated_at', 'created_by', 'updated_by')
    ordering = ('-created_at',)

@admin.register(CommentFiles)
class CommentFilesAdmin(admin.ModelAdmin):
    list_display = ('comment', 'comment_file', 'updated_on', 'created_at')
    list_filter = ('created_at', 'updated_on')
    search_fields = ('comment__comment',)
    readonly_fields = ('created_at', 'updated_at', 'created_by', 'updated_by', 'updated_on')
    ordering = ('-created_at',)
