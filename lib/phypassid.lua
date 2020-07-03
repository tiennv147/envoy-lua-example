json = require "lib.json"

PhyPassID = {}

local PHYPASS_ID = {
    USER_ID = "X-PhyPass-ID-UserID",
    CLIENT_ID = "X-PhyPass-ID-ClientID"
}

local function split(input_str, sep)
    if sep == nil then
        sep = "%s"
    end
    local t = {}
    local i = 1
    for str in string.gmatch(input_str, "([^" .. sep .. "]+)") do
        t[i] = str
        i = i + 1
    end
    return t
end

local function unauthorized(request_handle)
    request_handle:respond(
            {
                [":status"] = "401",
                ["Content-Type"] = "application/json",
                ["WWW-Authenticate"] = "oauth2"
            },
            "Please authenticate!"
    )
end

local function introspect_token(request_handle, headers, token)
    reqObj = {
        access_token = token,
        path = headers:get(":path"),
        method = headers:get(":method")
    }
    reqBody = json.encode(reqObj)
    request_handle:logInfo("PhyPassID.introspect call PhyPassID")
    resp_headers, resp_body = request_handle:httpCall(
            "phypass_id",
            {
                [":method"] = "POST",
                [":path"] = "/introspect",
                [":authority"] = "phypass_id"
            }, reqBody, 1000
    )
    request_handle:logInfo("PhyPassID.introspect resp body " .. resp_body)
    return resp_headers, json.decode(resp_body)
end

function PhyPassID.introspect(request_handle)
    request_handle:logInfo("PhyPassID.introspect start --- ")

    local headers = request_handle:headers()
    local metadata = request_handle:metadata()

    for key, value in pairs(headers) do
        request_handle:logInfo("PhyPassID.introspect header " .. key .. " - " .. value)
    end

    for key, value in pairs(metadata) do
        request_handle:logInfo("PhyPassID.introspect metadata " .. key .. " - " .. value)
    end

    local security = metadata:get("security")

    if security == nil or security == "public" then
        request_handle:headers():add("authority", "public")
        return
    end

    local auth = headers:get("Authorization")
    if auth == nil or string.len(auth) == 0 then
        unauthorized(request_handle)
    end
    local auth_parts = split(auth, " ")
    if #auth_parts < 2 then
        unauthorized(request_handle)
    end
    _token = auth_parts[2]
    resp_headers, resp_body = introspect_token(request_handle, headers, _token)
    request_handle:logInfo("PhyPassID.introspect header response: " .. resp_headers[":status"])
    if resp_headers[":status"] ~= "200" then
        unauthorized(request_handle)
    end

    if resp_body.userID ~= nil then
        request_handle:logInfo("PhyPassID.introspect UserID: " .. resp_body.userID)
        request_handle:headers():add(PHYPASS_ID.USER_ID, resp_body.userID)
    end

    if resp_body.clientID ~= nil then
        request_handle:logInfo("PhyPassID.introspect clientID: " .. resp_body.clientID)
        request_handle:headers():add(PHYPASS_ID.CLIENT_ID, resp_body.clientID)
    end

    request_handle:logInfo("PhyPassID.introspect DONE")
end

return PhyPassID