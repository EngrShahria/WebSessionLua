--[[
  For using this Module, you need weblit-cookies.lua
  It can be found here [ https://github.com/creationix/weblit/blob/master/libs/weblit-cookie.lua ]
]]

local digest = require("openssl").digest.digest
--[[ ALL AVAILABLE WAY TO HASH YOUR DATA
'RSA-MD4', 'RSA-MD5', 'RSA-RIPEMD160', 'RSA-SHA1', 'RSA-SHA1-2', 'RSA-SHA224', 'RSA-SHA256', 'RSA-SHA3-224',
'RSA-SHA3-256', 'RSA-SHA3-384', 'RSA-SHA3-512', 'RSA-SHA384', 'RSA-SHA512', 'RSA-SHA512/224', 'RSA-SHA512/256',
'RSA-SM3', 'blake2b512', 'blake2s256', 'id-rsassa-pkcs1-v1_5-with-sha3-224', 'id-rsassa-pkcs1-v1_5-with-sha3-256',
'id-rsassa-pkcs1-v1_5-with-sha3-384', 'id-rsassa-pkcs1-v1_5-with-sha3-512', 'md4', 'md4WithRSAEncryption', 'md5',
'md5-sha1', 'md5WithRSAEncryption', 'ripemd', 'ripemd160','ripemd160WithRSA', 'rmd160', 'sha1', 'sha1WithRSAEncryption',
'sha224', 'sha224WithRSAEncryption', 'sha256', 'sha256WithRSAEncryption', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512',
'sha384', 'sha384WithRSAEncryption', 'sha512', 'sha512-224', 'sha512-224WithRSAEncryption', 'sha512-256',
'sha512-256WithRSAEncryption', 'sha512WithRSAEncryption', 'shake128', 'shake256', 'sm3', 'sm3WithRSAEncryption',
'ssl3-md5','ssl3-sha1', 'whirlpool' 
]]

local object = require("core").Object
local WebSession = object:extend();

--[[
  Things you may need.
  User, isAuth, setAuth, setSessionTime
]]

math.randomseed(os.time() ^ 5)
local RandomString = function(length)
	local str = ""
	for i = 1, length do
		str = str .. string.char(math.random(97, 122))
	end
	return str
end

local ServerSession = {}

function WebSession:initialize(req, res, options)

    
    --SETUP THE OPTIONS 
    local options = options or {}
    if options.UserName == nil then return false end
    options.hash = "sha384"
    options.cName = options.cName or "ThisisCookie"
    options.length = options.length or 11
    options.secret = options.secret or "ThisIsSecretCode"
    ---

    local cName = digest("md5", options.cName);
    local SID = digest(options.hash, RandomString(options.length))
    
    --Set property based on every unique Object ID;
    self.SessionID = SID
    self.cName = cName
    self.Auth = true
    self.User = options.UserName
    self.Agent = digest(options.hash, req.headers["user-agent"])
    self.GenCode = digest("MD5", options.secret)

    

    --Initialize the server-side session;
    ServerSession = {}
    ServerSession[SID] = {}
    ServerSession[SID].UserName = self.User
    ServerSession[SID].isAuth = self.Auth
    ServerSession[SID].Agent = digest(options.hash, req.headers["user-agent"])
    ServerSession[SID].Protected = self.Agent .."/".. self.SessionID .. "=" .. self.GenCode 

    --Initialize the Response Cookie;
    res.setCookie(cName, SID);

end


--Other Methods;

function WebSession:isAuth(req) -- Check the person is has Auth Permission or
  local agent = digest("sha384", req.headers["user-agent"])
  local Protection = agent.."+"..self.SessionID .. "&".. self.GenCode
  local CodeName = req.cookies[self.cName]
  if ServerSession[CodeName].Protected == Protection then
    if self.Agent == ServerSession[CodeName].Agent then 
      if self.Auth == ServerSession[CodeName].isAuth then
      return true end
    end
  end
  return false
end

function WebSession:setAuth(bool) --Need to rework
  if bool ~= true or bool ~= false then return false end
  self.Auth = bool
  return true
end

function WebSession:getUser(req)
  if self.User == ServerSession[req.cookies[self.cName]].UserName then
    return self.User end
  return nil
end

function WebSession:getID() 
  return self.SessionID
end

function WebSession:destroy(req, res)
  local id = self.SessionID

 --Initialize the server-side session;
  ServerSession[id].UserName = nil
  ServerSession[id].isAuth = false
  ServerSession[id] = nil
  ServerSession = nil

  --Initialize the Response Cookie;
  res.clearCookie(self.cName);

  --Set property based on every unique Object ID;
  self.cName = nil
  self.SessionID = nil
  self.Auth = false
  self.User = nil
  return true
end


return WebSession
