# Generated by Django 3.2.8 on 2022-01-24 09:21

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Pool',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name_pool', models.CharField(max_length=100, null=True)),
                ('ip', models.GenericIPAddressField(null=True)),
                ('url', models.URLField(blank=True, null=True)),
                ('username', models.CharField(max_length=100, null=True)),
                ('type', models.CharField(max_length=1)),
            ],
            options={
                'db_table': 'POOL',
            },
        ),
    ]