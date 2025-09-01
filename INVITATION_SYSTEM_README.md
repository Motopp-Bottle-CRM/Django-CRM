# User Invitation System

This document explains how to use the user invitation system in the Django CRM application.

## Overview

The invitation system allows admin users to invite new users to join the organization. New users start as inactive and must set their password through an invitation link to become active.

## How It Works

1. **Admin creates user**: Admin user creates a new user through the API or admin panel
2. **User is inactive**: New user is created with `is_active=False` (both User and Profile)
3. **Invitation sent**: System automatically sends an invitation email with a unique token
4. **User sets password**: User clicks the invitation link and sets their password
5. **User activated**: Both User and Profile are set to `is_active=True`

## API Endpoints

### Create User (Admin Only)
```
POST /api/users/
```
- Creates a new user with inactive status
- Automatically sends invitation email
- Requires admin permissions

### List Users (Admin Only)
```
GET /api/users/
```
- Returns both active and inactive users
- Includes invitation status for inactive users
- Requires admin permissions

### Inactive Users List (Admin Only)
```
GET /api/users/inactive/
```
- Returns only inactive users with invitation details
- Requires admin permissions

### Resend Invitation (Admin Only)
```
POST /api/user/{user_id}/resend-invitation/
```
- Resends invitation email for a specific user
- Requires admin permissions

### Set Password from Invitation (Public)
```
GET /api/auth/set-password/{token}/
POST /api/auth/set-password/{token}/
```
- Public endpoint (no authentication required)
- GET: Returns invitation details
- POST: Sets password and activates user

## Admin Panel Features

### User Management
- View all users (active and inactive)
- Activate/deactivate users
- Create invitations for existing inactive users

### Invitation Management
- View all invitations with status
- Resend expired invitations
- Track invitation acceptance

### Admin Actions
- **Activate Users**: Bulk activate selected users
- **Deactivate Users**: Bulk deactivate selected users
- **Create Invitations**: Send invitations to selected inactive users
- **Resend Invitations**: Resend invitations to selected users

## Email Configuration

The system uses Mailhog for development:
- **SMTP Host**: localhost
- **SMTP Port**: 1025
- **TLS/SSL**: Disabled

## Testing the System

### Using Management Command
```bash
python manage.py test_invitation --email test@example.com --org "Test Organization"
```

### Manual Testing
1. Create a new user through admin panel or API
2. Check that user appears in inactive users list
3. Verify invitation email is sent (check Mailhog)
4. Click invitation link and set password
5. Verify user appears in active users list

## Security Features

- Invitation tokens expire after 7 days
- Tokens are unique and cannot be reused
- Only admin users can create invitations
- Non-admin users can only view their own profile
- Invitation links are public but secure

## Troubleshooting

### User not appearing in inactive tab
- Check if Profile.is_active is set to False
- Verify Profile.org matches the current organization
- Ensure User.is_active is False

### Invitation email not sent
- Check Mailhog is running on localhost:1025
- Verify Celery is running for background tasks
- Check email configuration in settings.py

### User cannot set password
- Verify invitation token is valid
- Check if invitation has expired
- Ensure invitation hasn't been used already

## File Structure

```
common/
├── models.py              # UserInvitation model
├── views.py               # API views for user management
├── admin.py               # Admin panel configuration
├── tasks.py               # Email sending tasks
├── templates/
│   └── user_invitation_email.html  # Email template
└── management/
    └── commands/
        └── test_invitation.py      # Testing command
```

## Dependencies

- Django
- Celery (for background email tasks)
- Mailhog (for email testing)
- Django REST Framework
