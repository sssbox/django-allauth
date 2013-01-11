import datetime

from django.core.urlresolvers import reverse
from django.db import models
from django.db import transaction
from django.utils.translation import ugettext_lazy as _
from django.utils import timezone
from django.contrib.sites.models import Site

from allauth import app_settings as allauth_app_settings
import app_settings
import signals

from utils import random_token
from managers import EmailAddressManager, EmailConfirmationManager
from adapter import get_adapter

class EmailAddress(models.Model):
    
    user = models.ForeignKey(allauth_app_settings.USER_MODEL, related_name='emailaddresses')
    email = models.EmailField(unique=app_settings.UNIQUE_EMAIL)
    verified = models.BooleanField(default=False)
    primary = models.BooleanField(default=False)
    
    objects = EmailAddressManager()
    
    class Meta:
        verbose_name = _("email address")
        verbose_name_plural = _("email addresses")
        if not app_settings.UNIQUE_EMAIL:
            unique_together = [("user", "email")]
    
    def __unicode__(self):
        return u"%s (%s)" % (self.email, self.user)
    
    def set_as_primary(self, conditional=False):
        old_primary = EmailAddress.objects.get_primary(self.user)
        if old_primary:
            if conditional:
                return False
            old_primary.primary = False
            old_primary.save()
        self.primary = True
        self.save()
        self.user.email = self.email
        self.user.save()
        return True
    
    def send_confirmation(self, request):
        confirmation = EmailConfirmation.create(self)
        confirmation.send(request)
        return confirmation
    
    def change(self, request, new_email, confirm=True):
        """
        Given a new email address, change self and re-confirm.
        """
        with transaction.commit_on_success():
            self.user.email = new_email
            self.user.save()
            self.email = new_email
            self.verified = False
            self.save()
            if confirm:
                self.send_confirmation(request)


class EmailConfirmation(models.Model):
    
    email_address = models.ForeignKey(EmailAddress)
    created = models.DateTimeField(default=timezone.now)
    sent = models.DateTimeField(null=True)
    key = models.CharField(max_length=64, unique=True)
    
    objects = EmailConfirmationManager()
    
    class Meta:
        verbose_name = _("email confirmation")
        verbose_name_plural = _("email confirmations")
    
    def __unicode__(self):
        return u"confirmation for %s" % self.email_address
    
    @classmethod
    def create(cls, email_address):
        key = random_token([email_address.email])
        return cls._default_manager.create(email_address=email_address, key=key)
    
    def key_expired(self):
        expiration_date = self.sent + datetime.timedelta(days=app_settings.EMAIL_CONFIRMATION_EXPIRE_DAYS)
        return expiration_date <= timezone.now()
    key_expired.boolean = True
    
    def confirm(self):
        if not self.key_expired() and not self.email_address.verified:
            email_address = self.email_address
            email_address.verified = True
            email_address.set_as_primary(conditional=True)
            email_address.save()
            signals.email_confirmed.send(sender=self.__class__, email_address=email_address)
            return email_address
    
    def send(self, request, **kwargs):
        summer_camp_url = reverse('summer_camp_create_signup', kwargs={'source':'camp_signup'})
        summer_camp_flow = summer_camp_url == request.REQUEST.get('next')
        current_site = kwargs["site"] if "site" in kwargs else Site.objects.get_current()
        activate_url = reverse("account_confirm_email", args=[self.key])
        activate_url = request.build_absolute_uri(activate_url)
        ctx = {
            "user": self.email_address.user,
            "activate_url": activate_url,
            "current_site": current_site,
            "key": self.key,
        }
        try:
            from brilliant.utils.tmail import send_tmail
        except:
            get_adapter().send_mail('account/email/email_confirmation',
                                self.email_address.email,
                                ctx)
        else:
            if hasattr(self.email_address, 'initial_signup') \
                    and self.email_address.initial_signup:
                if summer_camp_flow:
                    tpl = "utils/email_confirmation_summer_camp_welcome"
                else:
                    tpl = "utils/email_confirmation_welcome"
            else:
                tpl = "utils/email_confirmation"
            send_tmail(tpl, [self.email_address.email], ctx)
        self.sent = timezone.now()
        self.save()
        signals.email_confirmation_sent.send(sender=self.__class__, confirmation=self)





