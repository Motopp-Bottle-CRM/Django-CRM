#!/usr/bin/env python
"""
Migration Test Script for Team Members
=====================================

This script helps team members verify that migrations work correctly
without any prompts or issues.

Usage:
    python test_migrations.py

This script will:
1. Check current migration status
2. Apply any pending migrations
3. Verify the company field is properly configured
4. Test creating a lead with company name
"""

import os
import sys
import django
from django.core.management import execute_from_command_line

def setup_django():
    """Setup Django environment"""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'crm.settings')
    django.setup()

def test_migrations():
    """Test that migrations work without prompts"""
    print("🔍 Testing Migration Process...")
    print("=" * 50)
    
    # Check migration status
    print("1. Checking migration status...")
    execute_from_command_line(['manage.py', 'showmigrations', 'leads'])
    
    # Apply migrations
    print("\n2. Applying migrations...")
    execute_from_command_line(['manage.py', 'migrate', 'leads'])
    
    # Verify company field
    print("\n3. Verifying company field configuration...")
    from leads.models import Lead
    field = Lead._meta.get_field('company')
    print(f"   - Field type: {field.__class__.__name__}")
    print(f"   - Null allowed: {field.null}")
    print(f"   - Blank allowed: {field.blank}")
    print(f"   - Max length: {field.max_length}")
    
    # Test creating a lead
    print("\n4. Testing lead creation with company name...")
    try:
        # Test that company field accepts string values (no UUID validation)
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        # Get or create a test user
        user, created = User.objects.get_or_create(
            username='testuser',
            defaults={'email': 'test@example.com', 'first_name': 'Test', 'last_name': 'User'}
        )
        
        # This should work without any UUID validation errors
        test_lead = Lead(
            first_name="Test",
            last_name="User",
            company="Test Company",  # This is the key test - simple text, no UUID
            email="test@example.com",
            title="Test Lead",
            created_by=user,
            updated_by=user,
            organization=user.organization if hasattr(user, 'organization') else None,
            close_date="2024-12-31"
        )
        test_lead.full_clean()  # Validate without saving
        print("   ✅ Lead creation test passed!")
        print("   ✅ Company field accepts simple text (no UUID validation)")
    except Exception as e:
        print(f"   ❌ Lead creation test failed: {e}")
        return False
    
    print("\n✅ All migration tests passed!")
    print("Your teammate can safely run: python manage.py migrate")
    return True

if __name__ == "__main__":
    setup_django()
    success = test_migrations()
    sys.exit(0 if success else 1)
