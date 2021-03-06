from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth import get_user_model
from .models import User, SocialAuthenticatedUsers

class UserAdmin(BaseUserAdmin):

    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserAdmin
    # that reference specific fields on auth.User.
    list_display = ('user_id', 'email', 'admin')
    list_filter = ('admin', 'staff', 'admin')
    fieldsets = (
        ('Personal info', {'fields': ('email', 'password', 'first_name', 'last_name')}),
        ('Permissions', {'fields': ('admin', 'staff', 'active')}),
        ('provider details', {'fields': ('socialUserReference','source_provider', 'google_ID', 'facebook_ID')}),
    )
    # add_fieldsets is not a standard ModelAdmin attribute. UserAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'last_name', 'password1', 'password2')}
         ),
    )
    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('email',)
    filter_horizontal = ()


admin.site.register(User, UserAdmin)
admin.site.register(SocialAuthenticatedUsers)


#BUG in rest-famework-simpleJWT: in rest-famework overwrite the permision to delte oustanding tokens. so you can delete teh users
#RESOURCE: https://github.com/jazzband/djangorestframework-simplejwt/issues/266
from rest_framework_simplejwt import token_blacklist
class OutstandingTokenAdmin(token_blacklist.admin.OutstandingTokenAdmin):
    def has_delete_permission(self, *args, **kwargs):
        return True



admin.site.unregister(token_blacklist.models.OutstandingToken)
admin.site.register(token_blacklist.models.OutstandingToken, OutstandingTokenAdmin)
