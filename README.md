# WebSessionLua
Creating custom Web Session, based on weblit and Luvit.

If you are not familar with Luvit Objects, please check [Objects](https://luvit.io/api/core.html#core_class_core_object)

```Lua
local WebObject = require("WebSession")
--[[
Make a cookie, name it ID or anything ( I am using name ID )
and use that ID for TempVariable
]]
Local TempVariable[req.cookies.ID] = WebObject:new(req, res, {name = name, hash = "MD5", lenth = 5}) -- options: Name = username, hash = Hash method, Lenth for string
```

#Methods
:destroy() to destroy the whole session
:isAuth(req) to check the auth permissions
:getID() to get the session ID


#I will keep update the module soon!
