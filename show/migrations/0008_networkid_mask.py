# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2016-07-29 15:31
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('show', '0007_auto_20160729_1503'),
    ]

    operations = [
        migrations.AddField(
            model_name='networkid',
            name='mask',
            field=models.CharField(default=b'0.0.0.0', max_length=15),
        ),
    ]
