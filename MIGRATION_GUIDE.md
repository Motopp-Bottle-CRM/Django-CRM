# Migration Guide for Team Members

## Company Field Migration - Safe for All Team Members

This guide ensures that all team members can run migrations without encountering prompts or errors.

## What Was Changed

The `company` field in the `Lead` model has been changed from:
- **Before**: `ForeignKey` (required UUID validation)
- **After**: `CharField` (simple text field, required)

## Migration Files Created

1. **0007_alter_lead_company.py** - Changes field type to CharField (nullable)
2. **0008_auto_20250926_1530.py** - Populates NULL values with "Unknown Company"
3. **0009_auto_20250926_1532.py** - Makes field non-nullable using Django's AlterField
4. **0010_auto_20250926_1534.py** - Verification migration (safety check)

## For Team Members

### Option 1: Run Test Script (Recommended)
```bash
python test_migrations.py
```

### Option 2: Manual Migration
```bash
# Check migration status
python manage.py showmigrations leads

# Apply migrations (no prompts will appear)
python manage.py migrate leads

# Verify the field is working
python manage.py shell -c "from leads.models import Lead; print('Company field:', Lead._meta.get_field('company'))"
```

## What to Expect

✅ **No prompts or interactive questions**  
✅ **No UUID validation errors**  
✅ **Company field accepts simple text**  
✅ **All existing data preserved**  

## Testing the Changes

After running migrations, test creating a lead:

```python
from leads.models import Lead

# This should work without errors
lead = Lead(
    first_name="John",
    last_name="Doe", 
    company="Acme Corp",  # Simple text, no UUID needed
    email="john@acme.com"
)
lead.full_clean()  # Validates without saving
```

## Troubleshooting

If you encounter any issues:

1. **Check migration status**: `python manage.py showmigrations leads`
2. **Reset migrations** (if needed): 
   ```bash
   python manage.py migrate leads zero
   python manage.py migrate leads
   ```
3. **Run the test script**: `python test_migrations.py`

## Database Compatibility

These migrations work with:
- SQLite (development)
- PostgreSQL (production)
- MySQL (if used)
- Any Django-supported database

## Rollback (if needed)

To rollback the company field changes:
```bash
python manage.py migrate leads 0006  # Before company field changes
```

---

**Note**: All migrations are designed to be safe and non-interactive. Your teammate can run `python manage.py migrate` without any issues.
