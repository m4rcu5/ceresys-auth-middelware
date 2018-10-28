# CeReSys Authentication Middleware

This Lua middleware script is made for use with HAProxy and a CeReSys backend.

[CeReSys][1] is a Dutch made CRM for text-television. It provides a backend for editors to log in, but unfortunately no Active Directory or LDAP integration. That is what this middleware is here to resolve.

## `ceresys_auth`

The [CeReSys][1] backend uses basic authentication as login, combined with a session token. This part of the script will intercept this authentication and will do the following.
1. Decode the authentication response
2. Compare to the blacklist
3. Verify it is for our domain
4. Authenticate to LDAP backend
5. Generate backend authentication token
6. Set headers and forward response to backend

### Generating backend token

The backend should have the users set up with a username of `domain`-`username`. The password is a salted SHA1 hash of the username, which is inserted by the script to authenticate to the backend.
This string can be generated on the commandline using the following command:
`echo -n '{salt}{username}' | sha1sum | tr '[:lower:]' '[:upper:]'`
Where `username` is the username without the domain prefix.

Alternatively, you could use this [CyberChef recipe][2] to generate the password. Enter the salt on the fist line, and username on the second.

## `ceresys_realm`

In the `WWW-Authenticate` header send by [CeReSys][1], there is a timestamp included. As this breaks any password managers, this script can be used to remove this timestamp.

## Example configuration

An example of a valid backend configuration can be found below:
```
backend ceresys-srv.zfm.lan
    option httpchk

    http-request  lua.ceresys_auth 
    http-response lua.ceresys_realm
    http-request deny if { var(txn.auth_deny) -m bool }

    server srv ceresys-srv.zfm.lan:8080
```

## Dependencies

For LDAP authentication, we depend on [nginx-ldap-auth][3] project, handling the LDAP backend, providing a HTTP interface to interact with.

[1]: https://ceresys.nl/
[2]: https://gchq.github.io/CyberChef/#recipe=Remove_whitespace(true,true,true,true,true,false)SHA1()To_Upper_case(%27All%27)&input=bXlzZWNyZXRzYWx0CmYubGFzdG5hbWU
[3]: https://github.com/nginxinc/nginx-ldap-auth
