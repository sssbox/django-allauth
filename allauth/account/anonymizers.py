from allauth.account.models import EmailAddress, EmailConfirmation
from django.utils.timezone import make_aware, utc
from anonymizer import Anonymizer

similar_datetime = lambda anon, obj, field, val: make_aware(anon.faker.datetime(field=field, val=val), utc)

class EmailAddressAnonymizer(Anonymizer):

    model = EmailAddress

    attributes = [
        ('id', "SKIP"),
        ('email', "email"),
        ('user_id', "SKIP"),
        ('verified', "SKIP"),
        ('primary', "SKIP"),
    ]


class EmailConfirmationAnonymizer(Anonymizer):

    model = EmailConfirmation

    attributes = [
        ('id', "SKIP"),
        ('key', "varchar"),
        ('email_address_id', "SKIP"),
        ('created', similar_datetime),
        ('sent', similar_datetime),
    ]
