# Generated by Django 5.0.6 on 2024-06-23 09:49

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('walkieapi', '0007_recordmodel'),
    ]

    operations = [
        migrations.AddField(
            model_name='recordmodel',
            name='delivered',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='recordmodel',
            name='sender',
            field=models.OneToOneField(default=1, on_delete=django.db.models.deletion.CASCADE, related_name='record_sender', to='walkieapi.usermodel'),
            preserve_default=False,
        ),
    ]
