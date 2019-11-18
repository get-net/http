local fun = require("fun")

local sprintf = string.format

local _M = {}
local mt = {}

local default_options = {
    max_age = 3600,
    allow_credentials = true,
    allow_headers = {"Authorization, Content-Type"},
    allow_origin = {"*"}
}

function mt:__call(httpd, options)
    httpd.options['cors'] = default_options
    if type(options) == "table" then
        for k, v in next, options do
            if not default_options[k] then
                local msg = sprintf("Unsupported option %s", k)
                error(msg)
            end

            if type(v) ~= type(default_options[k]) then
                local msg = sprintf(
                    "Invalid type for option %s. Expected %s got %s",
                    k,
                    type(default_options[k]),
                    type(v)
                )
                error(msg)
            end

            if not httpd.options.cors then
                httpd.options.cors = {}
            end

            rawset(httpd.options.cors, k, v)
        end
    end

    _M.old_one = httpd.options.handler

    httpd.options.handler = function(self, ctx)
        if not self.options.cors then
            return
        end
        ctx.headers = {}

        local req_method = ctx.req.headers['access-control-request-method'] or ctx.req.method
        local req_headers = ctx.req.headers['access-control-request-headers']

        if req_headers then
            req_headers = req_headers:split(",")
        end

        local route = self:match(req_method, ctx.req.path)

        if not route then
            if ctx.req.method == "OPTIONS" then
                ctx:render({
                    status = 201,
                    text = ""
                })
                return ctx.res
            end
            return _M.old_one(self, ctx)
        end

        ctx.endpoint = route.endpoint

        if fun.any(function(v) return v=="*" end, self.options.cors.allow_origin) then
            ctx.headers["access-control-allow-origin"] = "*"
        else
            if fun.any(function(v) return v==ctx.req.headers["origin"] end, self.options.cors.allow_origin) then
                ctx.headers["access-control-allow-origin"] = ctx.req.headers["origin"]
            end
        end

        ctx.headers['access-control-max-age'] = self.options.cors.max_age
        ctx.headers['access-control-allow-credentials'] = tostring(self.options.cors.allow_credentials)
        ctx.headers['access-control-allow-headers'] = table.concat(self.options.cors.allow_headers, ",")

        if ctx.req.method == 'OPTIONS' then
            local methods
            if self.openapi then
                local path = self.openapi.paths[ctx.endpoint.openapi_path]

                if not path then
                    return
                end

                methods = fun.map(
                    function(k)
                        return k:upper()
                    end,
                    path
                ):totable()
            else
                methods = ctx.endpoint.method
            end

            if fun.any(function(val) return val == req_method end, methods) then
                ctx.headers['access-control-allow-methods'] = req_method
            end

            ctx:render({
                status = 201,
                text = ""
            })
            return ctx.res
        end

        return _M.old_one(self, ctx)
    end
end

setmetatable(_M, mt)

return _M
