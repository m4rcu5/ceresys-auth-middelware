local http = require("socket.http")

ceresys = {}

--
-- Configuration
--
ceresys.conf = {
    ldap_basedn = "OU=User Accounts,OU=Tolweg,DC=zfm,DC=lan",
    ldap_filter = "(&" ..
        "(objectCategory=Person)(sAMAccountName=%(username)s)" ..
            "(|" ..
                "(memberOf=CN=TV Tekst Redactie,OU=User Accounts,OU=Tolweg,DC=zfm,DC=lan)" ..
                "(memberOf=CN=TV Video Redactie,OU=User Accounts,OU=Tolweg,DC=zfm,DC=lan)" ..
            ")" ..
        ")",
    auth_server   = "http://127.0.0.1:8888",
    password_salt = "uqUBKrZ5s19m",
    deny_users    = { "admin", "*playout*" },
    local_domain  = "ZFM"
}

-- Authorization cache table
ceresys.authcache = {}

--
-- CeReSys authentication middleware
--
ceresys.auth = function(txn)
    -- Extract login details from headers
    local username, password = getBasicAuthLogin(txn)

    -- If the the request did not contain a username
    -- we return the request unchanged to the backend.
    if not username or not password then
        txn:Debug("No username/password decoded in authorization header")
        return
    end

    -- Check if the user is in the deny list
    if hasValue(ceresys.conf["deny_users"], username) then
        txn:Info("User is in deny_users list: " .. username)
        txn:set_var("txn.auth_deny", true)

        dropAuthorizationHeader(txn); return
    end

    -- Detect domain authentication bypass
    if username:match("^" .. ceresys.conf["local_domain"]:lower() .. "%-") then
        txn:Info("Direct backend login detected for: " .. username)
        txn:set_var("txn.auth_deny", true)

        dropAuthorizationHeader(txn); return
    end

    -- Determine if the user is in our domain
    if not username:match("^" .. ceresys.conf["local_domain"] .. "\\") then
        txn:Debug("Username not containing domain prefix")
        return
    end

    -- Strip local_domain from username
    local username = username:match("^" .. ceresys.conf["local_domain"] .. "\\" .. "(.+)")

    -- Validate user credentials with backend service
    local auth_status = validateAccess(txn, username, password)

    -- Authorize to backend if we authenticated sucessfully
    if auth_status then
        txn:Debug("User authenticated: " .. username)

        injectAuthorizationHeader(txn, username)
    else
        txn:Info("User authentication failed: " .. username)

        dropAuthorizationHeader(txn); return
    end
end

--
-- Remove timestamp from CeReSys Realm
--
-- The included timestamp breaks password managers. If the response contains a WWW-Authenticate
-- header, we sanitize it.
--
ceresys.realm = function(txn)
    local auth_hdr = txn.http:res_get_headers()["www-authenticate"]

    if auth_hdr ~= nil then
        -- Example header: Basic realm="CeReSys - ZFM Zandvoort(23:09:13)"
        local new_realm = (auth_hdr[0]:gsub('%(%d+:%d+:%d+%)', ''))
        txn.http:res_set_header("www-authenticate", new_realm)
    end
end

--
-- Remove the authentication header from the request
--
function dropAuthorizationHeader(txn)
    txn.http:req_del_header('authorization')
end

--
-- Inject the backend 'authorization' header
--
-- Backend users are prefixed with a lowercase 'local_domain' and use a salted
-- sha1 hash of the username as password.
--
-- To generate a password for the backend use the following command:
-- echo -n '{salt}{username}' | sha1sum | tr '[:lower:]' '[:upper:]'
--
function injectAuthorizationHeader(txn, username)
    local salt   = ceresys.conf.password_salt
    local prefix = ceresys.conf.local_domain:lower() .. '-'

    -- Generate a salted sha1 hash
    local hash_bin = txn.c:sha1(salt .. username)
    local hash_hex = txn.c:hex(hash_bin)
    -- Prefix username and create Basic (base64) string
    local base64   = txn.c:base64(prefix .. username .. ':' .. hash_hex)
    local auth_hdr = "Basic " .. base64

    -- Replace the existing 'authorization' header in the request
    txn.http:req_set_header('authorization', auth_hdr)
end

--
-- Return the cleartext username and password extracted from the 'Authorization' header
--
function getBasicAuthLogin(txn)
    local authorization_hdr = txn.http:req_get_headers()['authorization']

    -- No auth header leaves nothing to do
    if authorization_hdr == nil then
        txn:Debug("Empty Authorization header")
        return
    end

    -- Only look at the first Authorization header
    local authorization = authorization_hdr[0]

    -- Invalid basic authentication headers
    if not authorization:find("Basic ") == 1 then
        txn:Warning("Not basic auth - authorization=" .. authorization)
        return
    end

    -- Decode the authorization header
    local encoded = authorization:match("Basic%s+(.*)")
    local decoded = txn.c:b64dec(encoded)

    -- Extract username and password
    local username, password = decoded:match("([^:]*):(.*)")

    return username, password
end


--
-- LDAP Authentication handler
--
-- Calls our authentication backend, in this case 'nginx-ldap-auth'
-- and return true if the user was authenticated, false if anything went wrong.
--
function validateAccess(txn, username, password)
    local authhash   = nil
    local cookie_hdr = txn.http:req_get_headers()['cookie']

    -- Check if we have a Cookie set
    if cookie_hdr ~= nil then
        local session_id = nil

        -- Extract the correct session Cookie
        for _, hdr in pairs(cookie_hdr) do
            local id = hdr:match('IDHTTPSESSIONID=(.+)')

            if id ~= nil then
                session_id = id
                txn:Debug("Detected session id in cookie header: " .. session_id)
            end
        end

        -- Generate a auth hash based on session_id and password
        authhash = txn.c:sha1(password .. session_id)

        -- Check if we already authenticated this session
        if ceresys.authcache[username] ~= nil then
            if ceresys.authcache[username] == authhash then
                txn:Debug("Matched session/password to auth cache")
                return true
            else
                txn:Debug("Removing stale entry from auch cache")
                ceresys.authcache[username] = nil
            end
        end
    end

    -- Create a new Authorization header for our auth provider
    local decoded = username .. ":" .. password
    local encoded = txn.c:base64(decoded)

    local auth_hdr = "Basic " .. encoded

    -- Make the call to the auth provider
    local b, c, h = http.request {
        url = ceresys.conf.auth_server,
        headers = {
            ["authorization"]   = auth_hdr,
            ["X-Ldap-BaseDN"]   = ceresys.conf.ldap_basedn,
            ["X-Ldap-Template"] = ceresys.conf.ldap_filter
        },
        redirect = false
    }

    -- Check whether we received a valid HTTP response.
    if b == nil then
        return false
    end

    -- 2xx: Allow request.
    if 200 <= c and c < 300 then
        txn:Debug("Authenticated user to LDAP backend, adding to cache")
        ceresys.authcache[username] = authhash

        return true
    -- 401 / 403: Do not allow request.
    elseif c == 401 or c == 403 then
        return false
    -- Everything else: Do not allow request and log.
    else
        txn:Warning("Invalid status code in authentication provider: " .. c)
        return false
    end

    return false
end

--
-- Find value in array
--
function hasValue (tab, val)
    for index, value in ipairs(tab) do
        if value == val then
            return true
        end
    end

    return false
end

-- Register the CeReSys authentication handler
core.register_action("ceresys_auth", { "http-req" }, ceresys.auth);

-- Register the CeReSys realm sanitizer
core.register_action("ceresys_realm", { "http-res" }, ceresys.realm);
