# Generated by Django 4.0.3 on 2022-04-03 10:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0002_user_mobile_no_user_name'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='mobile_no',
            field=models.CharField(max_length=12, unique=True, verbose_name='mobile_no'),
        ),
    ]
