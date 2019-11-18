<a href="http://tarantool.org">
   <img src="https://avatars2.githubusercontent.com/u/2344919?v=2&s=250"
align="right">
</a>

# HTTP server for Tarantool 1.7.5+

[![Build Status](https://travis-ci.org/tarantool/http.png?branch=tarantool-1.7)](https://travis-ci.org/tarantool/http)

> **Note:** In Tarantool 1.7.5+, a full-featured HTTP client is available aboard.
> For Tarantool 1.6.5+, both HTTP server and client are available
> [here](https://github.com/tarantool/http/tree/tarantool-1.6).

## Table of contents

* [Prerequisites](#prerequisites)
* [Installation](#installation)
* [Usage](#usage)
* [Creating a server](#creating-a-server)
* [Using routes](#using-routes)
* [Contents of app\_dir](#contents-of-app_dir)
* [Route handlers](#route-handlers)
  * [Fields and methods of the Request object](#fields-and-methods-of-the-request-object)
  * [Fields and methods of the Response object](#fields-and-methods-of-the-response-object)
  * [Examples](#examples)
* [Working with stashes](#working-with-stashes)
  * [Special stash names](#special-stash-names)
* [Working with cookies](#working-with-cookies)
* [Rendering a template](#rendering-a-template)
* [Template helpers](#template-helpers)
* [Hooks](#hooks)
  * [handler(ctx)](#handlerctx)
  * [before\_dispatch(ctx)](#before_dispatchctx)
  * [after\_dispatch(ctx)](#after_dispatchctx)
* [Hook mapping](#hook-mapping)
* [CORS handling](#cors-handling)
* [OpenAPI support](#openapi-support)
* [See also](#see-also)

## Prerequisites

 * Tarantool 1.7.5+ with header files (`tarantool` && `tarantool-dev` packages)

## Installation

You can:

* clone the repository and build the `http` module using CMake:

  ``` bash
  git clone https://github.com/tarantool/http.git
  cd http && cmake . -DCMAKE_BUILD_TYPE=RelWithDebugInfo
  make
  make install
  ```

* install the `http` module using `tarantoolctl`:

  ``` bash
  tarantoolctl rocks install http
  ```

* install the `http` module using LuaRocks
  (see [TarantoolRocks](https://github.com/tarantool/rocks) for
  LuaRocks configuration details):

  ``` bash
  luarocks install https://raw.githubusercontent.com/tarantool/http/master/rockspecs/http-scm-1.rockspec --local
  ```

## Usage

The server is an object which is configured with HTTP request
handlers, routes (paths), templates, and a port to bind to.
Unless Tarantool is running under a superuser, port numbers
below 1024 may be unavailable.

The server can be started and stopped anytime. Multiple
servers can be created.

To start a server:

1. [Create it](#creating-a-server) with `httpd = require('http.server').new(...)`.
2. [Configure routing](#using-routes) with `httpd:route(...)`.
3. Start it with `httpd:start()`.

To stop the server, use `httpd:stop()`.

## Creating a server

```
httpd = require('http.server').new(host, port[, { options } ])
```

`host` and `port` must contain: 
* For tcp socket: the host and port to bind to.
* For unix socket: `unix/` and path to socket (for example `/tmp/http-server.sock`) to bind to. 

`options` may contain:

* `max_header_size` (default is 4096 bytes) - a limit for
  HTTP request header size.
* `header_timeout` (default: 100 seconds) - a timeout until
  the server stops reading HTTP headers sent by the client.
  The server closes the client connection if the client doesn't
  send its headers within the given amount of time.
* `app_dir` (default is '.', the server working directory) -
  a path to the directory with HTML templates and controllers.
* `handler` - a Lua function to handle HTTP requests (this is
  a handler to use if the module "routing" functionality is not
  needed).
* `charset` - the character set for server responses of
  type `text/html`, `text/plain` and `application/json`.
* `display_errors` - return application errors and backtraces to the client
  (like PHP).
* `log_requests` - log incoming requests. This parameter can receive:
    - function value, supporting C-style formatting: log_requests(fmt, ...), where fmt is a format string and ... is Lua Varargs, holding arguments to be replaced in fmt.
    - boolean value, where `true` choose default `log.info` and `false` disable request logs at all.

  By default uses `log.info` function for requests logging.
* `log_errors` - same as the `log_requests` option but is used for error messages logging. By default uses `log.error()` function.

## Using routes

It is possible to automatically route requests between different
handlers, depending on the request path. The routing API is inspired
by [Mojolicious](http://mojolicio.us/perldoc/Mojolicious/Guides/Routing) API.

Routes can be defined using:

* an exact match (e.g. "index.php")
* simple regular expressions
* extended regular expressions

Route examples:

```text
'/'                 -- a simple route
'/abc'              -- a simple route
'/abc/:cde'         -- a route using a simple regular expression
'/abc/:cde/:def'    -- a route using a simple regular expression
'/ghi*path'         -- a route using an extended regular expression
```

To configure a route, use the `route()` method of the `httpd` object:

```lua
httpd:route({ path = '/path/to' }, 'controller#action')
httpd:route({ path = '/', template = 'Hello <%= var %>' }, handle1)
httpd:route({ path = '/:abc/cde', file = 'users.html.el' }, handle2)
httpd:route({ path = '/objects', method = 'GET' }, handle3)
httpd:route({ path = '/users', method = {"PUT", "POST", "DELETE"}}, handle4)
```

The first argument for `route()` is a Lua table with one or more keys:

* `file` - a template file name (can be relative to.
  `{app_dir}/templates`, where `app_dir` is the path set when creating the
  server). If no template file name extension is provided, the extension is
  set to ".html.el", meaning HTML with embedded Lua.
* `template` - template Lua variable name, in case the template
  is a Lua variable. If `template` is a function, it's called on every
  request to get template body. This is useful if template body must be
  taken from a database.
* `path` - route path, as described earlier.
* `name` - route name.
* `method` - method on the route like `POST`, `GET`, `PUT`, `DELETE`, also may be a table of those.
* `log_requests` - option that overrides the server parameter of the same name but only for current route.
* `log_errors` - option that overrides the server parameter of the same name but only for current route.

The second argument is the route handler to be used to produce
a response to the request.

The typical usage is to avoid passing `file` and `template` arguments,
since they take time to evaluate, but these arguments are useful
for writing tests or defining HTTP servers with just one "route".

The handler can also be passed as a string of the form 'filename#functionname'.
In that case, the handler body is taken from a file in the
`{app_dir}/controllers` directory.

## Contents of `app_dir`

* `public` - a path to static content. Everything stored on this path
  defines a route which matches the file name, and the HTTP server serves this
  file automatically, as is. Notice that the server doesn't use `sendfile()`,
  and it reads the entire content of the file into the memory before passing
  it to the client. ??? Caching is not used, unless turned on. So this is not
  suitable for large files, use nginx instead.
* `templates` -  a path to templates.
* `controllers` - a path to *.lua files with Lua controllers. For example,
  the controller name 'module.submodule#foo' is mapped to
  `{app_dir}/controllers/module.submodule.lua`.

## Route handlers

A route handler is a function which accepts one argument (**Context**) and
returns response object, which is set inside the **Context** object by the index of **res**.

```lua
function my_handler(self)
    -- self is a Context object
    self:render({
        status = 201,
        headers = {
            ['x-test-header'] = 'test'
        },
        text = self.req.method..' '..self.req.path
    })

    -- res object within Context will be handled automatically
end
```

### Fields and methods of the Context object

* `ctx.req.body` - request's body
* `ctx.req.method` - HTTP request type (`GET`, `POST` etc).
* `ctx.req.path` - request path.
* `ctx.req.query` - request arguments.
* `ctx.req.proto` - HTTP version (for example, `{ 1, 1 }` is `HTTP/1.1`).
* `ctx.req.headers` - normalized request headers. A normalized header
  is in the lower case, all headers joined together into a single string.
* `ctx.peer` - a Lua table with information about the remote peer
  (like `socket:peer()`).
* `tostring(ctx)` - returns a string representation of the request.
* `ctx:request_line()` - returns the request body.
* `ctx:read(delimiter|chunk|{delimiter = x, chunk = x}, timeout)` - reads the
  raw request body as a stream (see `socket:read()`).
* `ctx:json()` - returns a Lua table from a JSON request.
* `ctx:post_param(name)` - returns a single POST request a parameter value.
  If `name` is `nil`, returns all parameters as a Lua table.
* `ctx:query_param(name)` - returns a single GET request parameter value.
  If `name` is `nil`, returns a Lua table with all arguments.
* `ctx:param(name)` - any request parameter, either GET or POST.
* `ctx:cookie(name)` - to get a cookie in the request.
* `ctx:stash(name[, value])` - get or set a variable "stashed"
  when dispatching a route.
* `ctx:url_for(name, args, query)` - returns the route's exact URL.
* `ctx:render({})` - create a **Response** object with a rendered template.
* `ctx:redirect_to(name, [args], query)` - create a **Response** object with an HTTP redirect.

### Fields and methods of the Response object

* `ctx.res.status` - HTTP response code.
* `ctx.res.headers` - a Lua table with normalized headers.
* `ctx.res.body` - response body (string|table|wrapped\_iterator).
* `ctx:setcookie({ name = 'name', value = 'value', path = '/', expires = '+1y', domain = 'example.com'))` -
  adds `Set-Cookie` headers to `ctx.res.headers`.

### Examples

```lua
function my_handler(self)
    return {
        status = 200,
        headers = { ['content-type'] = 'text/html; charset=utf8' },
        body = [[
            <html>
                <body>Hello, world!</body>
            </html>
        ]]
    }
end
```

## Working with stashes

```lua
function hello(self)
    local id = self:stash('id')    -- here is :id value
    local user = box.space.users:get(id)
    if user then
        self:redirect_to('/users_not_found')
        return
    end
    self:render({ user = user })
end

httpd = httpd.new('127.0.0.1', 8080)
httpd:route(
    { path = '/:id/view', template = 'Hello, <%= user.name %>' }, hello)
httpd:start()
```

### Special stash names

* `controller` - the controller name.
* `action` - the handler name in the controller.
* `format` - the current output format (e.g. `html`, `txt`). Is
  detected automatically based on the request's `path` (for example, `/abc.js`
  sets `format` to `js`). When producing a response, `format` is used
  to serve the response's 'Content-type:'.

## Working with cookies

To get a cookie, use:

```lua
function show_user(self)
    local uid = self:cookie('id')

    if uid and string.match(uid, '^%d$') ~= nil then
        local user = box.space.users:get(uid)

        if user then
            self:render({
                json = {
                    user = user
                }
            })
            return
        end
    end

    self:redirect_to('/login')
end
```

To set a cookie, use the `setcookie()` method of a response object and pass to
it a Lua table defining the cookie to be set:

```lua
local sprintf = string.format
function user_login(self)
    local login = self:param('login')
    local password = self:param('password')

    -- presume we have "users" space with unique index for login and password
    local user = box.space.users.index.login_password:get({login, password})
    if user then
        self:redirect_to('/')
        self:setcookie({ name = 'uid', value = user[0], expires = '+1y' })
        return
    end

    -- sets resp to redirect back to login page
    self:redirect_to('/login')

    -- just an example of cookie deletion
    if self:cookie("uid") then
        self:setcookie({ name = 'uid', value = "", expires = '0m' })
    end
end
```

The table must contain the following fields:

* `name`
* `value`
* `path` (optional; if not set, the current request path is used)
* `domain` (optional)
* `expires` - cookie expire date, or expire offset, for example:

  * `1d`  - 1 day
  * `+1d` - the same
  * `23d` - 23 days
  * `+1m` - 1 month(not necessarily 30 days)
  * `+1y` - 1 year

## Rendering a template

Lua can be used inside a response template, for example:

```html
<html>
    <head>
        <title><%= title %></title>
    </head>
    <body>
        <ul>
            % for i = 1, 10 do
                <li><%= item[i].key %>: <%= item[i].value %></li>
            % end
        </ul>
    </body>
</html>
```

To embed Lua code into a template, use:

* `<% lua-here %>` - insert any Lua code, including multi-line.
  Can be used anywhere in the template.
* `% lua-here` - a single-line Lua substitution. Can only be
  present at the beginning of a line (with optional preceding spaces
  and tabs, which are ignored).

A few control characters may follow `%`:

* `=` (e.g., `<%= value + 1 %>`) - runs the embedded Lua code
  and inserts the result into HTML. Special HTML characters,
  such as `<`, `>`, `&`, `"`, are escaped.
* `==` (e.g., `<%== value + 10 %>`) - the same, but without
  escaping.

A Lua statement inside the template has access to the following
environment:

1. Lua variables defined in the template,
1. stashed variables,
1. variables standing for keys in the `render` table.

## Template helpers

Helpers are special functions that are available in all HTML
templates. These functions must be defined when creating an `httpd` object.

Setting or deleting a helper:

```lua
-- setting a helper
httpd:helper('time', function(self, ...) return box.time() end)
-- deleting a helper
httpd:helper('some_name', nil)
```

Using a helper inside an HTML template:

```html
<div>
    Current timestamp: <%= time() %>
</div>
```

A helper function can receive arguments. The first argument is
always the current controller. The rest is whatever is
passed to the helper from the template.

## Hooks

It is possible to define additional functions invoked at various
stages of request processing.

### `handler(ctx)`

If `handler` is present in `httpd` options, it gets
involved on every HTTP request, and the built-in routing
mechanism is unused (no other hooks are called in this case).

### `before_dispatch(ctx)`

Is invoked before a request is routed to a handler. The only
argument of the hook is the HTTP request to be handled.
The hook may render and return responses.

This hook may be used to add headers to response or authorize requests.

#### Usage examples

```lua
-- CORS request handling implementation
function before(self)
    -- for static file response, there is a flag inside of context object
    if self.static then
        return
    end

    self.headers = {
        ["Access-Control-Allow-Origin"]      = "*",
        ["Access-Control-Max-Age"]           = 3600,
        ["Access-Control-Allow-Credentials"] = "true",
        ["Access-Control-Allow-Headers"]     = "Authorization, Content-Type, X-Requested-With"
    }

    --[[
        Intercepts OPTIONS request before sending it to an actual handler
        assigned to this endpoint.
        Renders empty-bodied plain/text response with all the headers above,
        also adds Access-Control-Allow-Methods header from the render method
        below.
    ]]
    if self.req.method == "OPTIONS" then
        self:render({
            status = 201,
            headers = {
                ['Access-Control-Allow-Methods'] = "GET, HEAD, POST"
            },
            text = ""
        })
        return
    end

    return
end
```

```lua
function before(self)
    -- assuming there's a Bearer token Authorization
    local token = self.req.headers['Authorization']

    if not token or not some_authentication_method(token) then
        -- intercept with 401 UNAUTHORIZED response
        self:render({
            status = 401,
            json = {
                result = false,
                error  = "Unauthorized"
            }
        })
        return
    end

    return
end
```


### `after_dispatch(ctx)`

Is invoked after a handler for a route is executed.

The arguments of the hook are the context passed into the handler,
with response object inside.

This hook can be used to modify the response.
The return value of the hook is ignored.

#### Example
```lua
function after(self)
    -- for example, we need to add a header to response
    self.res.headers["Content-Type"] = "application/json"

    -- or change it's status
    self.res.status = 404

    -- or even body
    self.res.body = json.encode({
        result = false,
        error = "Interfered with by after_dispatch hook"
    })
end
```

## Hook mapping
```lua
-- assigning before hook to httpd object
httpd:hook("before_dispatch", some_before_function)

-- also valid
httpd.hooks.after_dispatch = some_after_function
```

## CORS handling
Module cors is a wrapper that takes current server instance as the first argument and
`allow` options as the second. The second argument is optional, and if it's not set then
the default options take it's place.

#### Example
```lua
local httpd = require("http.server").new(nil, 5000)
local cors  = require("http.cors")

-- this call returns nothing, just maps some methods
cors(httpd, {
    max_age = 18400, -- default value 3600
    allow_credentials = false, -- default value true
    allow_headers = {"Authorization", "Content-Type", "X-Requested-With"}, -- default {"Authorization", "Content-Type"} 
    allow_origin = {"http://example.com"} -- default {"*"}
})

httpd:route({path="/api/user", method="GET"}, some_handler)

httpd:start()
```

## OpenAPI support
You may use your openapi specification file to map the routes and handlers inside your project.

#### Quickstart
```lua
local server  = require("http.server").new(nil, 5000)
local openapi = require("http.openapi")

local httpd = openapi(server, 'api.yaml', {
    security = require("authorization")
})

httpd:start()
```
As you can see, openapi call takes three positional arguments, which are:
server instance, path to read specification file from and also a table with
options(only takes security for now).


#### Routing
The openapi module uses `opeartionId` and `tags` options from [operation object](https://github.com/OAI/OpenAPI-Specification/blob/master/versions/2.0.md#operation-object)
to map controller function to the route. For example, you wrote a `./controllers/example.lua` module:

```lua
local _M = {}
function _M.userinfo(self)
   -- some code here
   return self:render({
       json = {   
            data = user_data
       }
   })
end

return _M
```

Operation object from spec file should look something like this:
```yaml
tags:
- example
operationId: 'userinfo'
parameters:
  - in: query
  name: id
  required: true
  schema:
    type: string
```
So, the module will map `GET /example` request to be handled by `userinfo` function in `controllers.example` module.
All the modules must be stored within the `controllers` directory, because the module exploits tarantool-http's ability
to map handlers with a `controller#action` string. Place your controller modules inside the **controllers** folder, relative
to your `app_dir` option.

The controller module may also return a function instead of a table, in that case just make sure your `example.lua` module
returns the handler itself and drop the operationId from operation object schema.

Note that the module maps only the first tag of the list, every other tag would be ignored.

#### Security Example

The `security` option contains either a table of methods to handle security schemas described
in your spec-file, or a function if you don't have multiple authorization protocols.

api.yaml
```yaml
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
    apiKeyAuth:
      type: apiKey
      in: header
      name: X-API-KEY
    basicAuth:
      type: http
      scheme: basic
```

authorization.lua file
```lua
local _M = {}

function _M.bearerAuth(url, scopes, token)
    -- validate token
    return result, err
end

function _M.apiKeyAuth(url, scopes, api_key)
    -- validate API-key
    return result, err
end

function _M.basicAuth(url, scopes, username, password)
    -- validate user credentials
    return result, err
end

return _M
```
The module correlate those automatically by the name of security scheme and method.
and also sends corresponding arguments to the function. The basic authorization header is
decoded from base64 and also splits by ":" symbol to form username and password.

The `url` argument is the current request's path, taken from `request_object.req.path`.
The scopes are sent from the security option in the operation object schema:
```yaml
post:
  tags:
  - example
  operationId: 'userinfo'
  summary: 'Example request'
  security:
    - bearerAuth: ['test_scope', 'example_scope', 'etc_scope'] #here they are
  ...
```
As for token, api_key and username\password pair: those are, obviously, your authorization data,
that needs to be checked in order to proceed with the request handling process.

Authorization functions must return two values. In case of an error, be sure to `return nil, error_string`,
in case of successful authorization just return current user's data, that you may later access inside your
controller function. For example, inside of our `controllers/example.lua` described above:

```lua
function userinfo(self)    
    local user_data = self.authorization

    return self:render({
        json = {
            data = user_data
        }
    })
end
```

You may also override default error handling with a function:

```lua
local server  = require("http.server").new(nil, 5000)
local openapi = require("http.openapi")

local httpd = openapi(server, 'api.yaml', {
    security = require("authorization")
})

-- the default return value
-- ctx is a context value, that is a request object here
httpd:default(
    function(ctx, err)
        return ctx:render({
            status = 204,
            json = {
                success = false,
                message = err,
                error   = "No Content"
            }
        })
    end
)

-- this will catch all request validation exceptions, etc. 
httpd:error_handler(
    function(ctx, err)
        -- err argument here will be a table most of the time
        return ctx:render({
            json = {
                success = false,
                errors  = err    
            }   
        })
    end
)

-- the second return value of our `bearerAuth`, `apiKeyAuth` and `basicAuth` functions will be here
httpd:security_error_handler(
    function(ctx, err)
        return self:render({
            status = 401,
            json = {
                success = false,
                error   = "Unauthorized",
                message = err
            }   
        })
    end
)
```

You can also wrap openapi return value inside the cors call:
```lua
local server  = require("http.server").new(nil, 5000)
local openapi = require("http.openapi")

local httpd = openapi(server, 'api.yaml', {
    security = require("authorization")
})

cors(httpd)
```

The default CORS options should suffice for the development process.

## See also

 * [Tarantool project][Tarantool] on GitHub
 * [Tests][] for the `http` module

[Tarantool]: http://github.com/tarantool/tarantool
[Tests]: https://github.com/tarantool/http/tree/master/test
