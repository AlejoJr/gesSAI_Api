# Generated by Django 3.2.8 on 2022-01-25 12:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('group', '0003_alter_group_name_group'),
    ]

    operations = [
        migrations.AlterField(
            model_name='group',
            name='user',
            field=models.CharField(max_length=100, null=True),
        ),
    ]
