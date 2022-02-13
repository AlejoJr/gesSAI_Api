# Generated by Django 3.2.8 on 2022-02-08 23:22

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('host', '0002_alter_host_description'),
    ]

    operations = [
        migrations.AlterField(
            model_name='host',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='host', to=settings.AUTH_USER_MODEL),
        ),
    ]
