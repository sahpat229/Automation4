# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2016-07-14 14:39
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('show', '0004_delete_user'),
    ]

    operations = [
        migrations.CreateModel(
            name='HostFiles',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('os', models.CharField(max_length=200)),
                ('func', models.CharField(max_length=200)),
                ('lines', models.FilePathField(path=b'/etc/ansible/showsite/show/hostlists')),
            ],
        ),
    ]
