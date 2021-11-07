package com.isaccanedo.javaee.security;

import javax.enterprise.context.ApplicationScoped;
import javax.security.enterprise.authentication.mechanism.http.FormAuthenticationMechanismDefinition;
import javax.security.enterprise.authentication.mechanism.http.LoginToContinue;
import javax.security.enterprise.identitystore.LdapIdentityStoreDefinition;

@FormAuthenticationMechanismDefinition(
        loginToContinue = @LoginToContinue(
                loginPage = "/login.html",
                errorPage = "/login-error.html"
        )
)
@LdapIdentityStoreDefinition(
        url = "ldap://localhost:10389",
        callerBaseDn = "ou=caller,dc=isaccanedo,dc=com",
        groupSearchBase = "ou=group,dc=isaccanedo,dc=com",
        groupSearchFilter = "(&(member=%s)(objectClass=groupOfNames))"
)
@ApplicationScoped
public class AppConfig {
}
