# Generated by Django 5.0.6 on 2024-06-27 13:58

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('walkieapi', '0014_rename_delivered_pairmodel_receiver_delivered_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='pairmodel',
            name='receiver_delivered',
        ),
        migrations.RemoveField(
            model_name='pairmodel',
            name='sender_delivered',
        ),
    ]
