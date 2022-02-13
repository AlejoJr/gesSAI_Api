# Generated by Django 3.2.8 on 2022-01-24 09:21

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Sai',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip', models.GenericIPAddressField(null=True)),
                ('name_sai', models.CharField(max_length=100)),
                ('url', models.URLField(null=True)),
                ('type', models.CharField(max_length=1)),
                ('state', models.CharField(max_length=50)),
                ('responsible', models.CharField(max_length=100)),
                ('code_oid', models.CharField(max_length=100)),
                ('value_off', models.CharField(max_length=50)),
                ('value_on', models.CharField(max_length=50)),
            ],
            options={
                'db_table': 'SAI',
            },
        ),
    ]
