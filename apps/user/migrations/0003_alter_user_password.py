# Generated by Django 3.2.8 on 2022-02-08 23:26

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0002_auto_20220209_0022'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='password',
            field=models.CharField(default=django.utils.timezone.now,max_length=128, verbose_name='password'),
        ),
    ]
