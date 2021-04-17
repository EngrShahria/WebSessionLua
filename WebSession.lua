--[[
  For using this Module, you need weblit-cookies.lua
  It can be found here [ https://github.com/creationix/weblit/blob/master/libs/weblit-cookie.lua ]

  Usage: 
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

function WebSession:initialize(req, res, options)

    --SETUP THE OPTIONS 
    local options = options or {}
    if options.name == nil then return false end
    options.hash = options.hash or "md5WithRSAEncryption"
    options.length = options.length or 5

    local sid = digest(options.hash, RandomString(options.length))

    --Initialize the server-side session;
    req.session = {}
    req.session[sid] = {}
    req.session[sid].user = options.name
    req.session[sid].isAuth = true
    --Initialize the Response Cookie;

    res.setCookie("sID", sid);

    --Set property based on every unique Object ID;
    self.SessionID = sid;
    self.Auth = true
    self.User = req.session[sid].user

end

function WebSession:getID()
  return self.SessionID
end

function WebSession:setAuth(bool)
  if bool ~= true or bool ~= false then return false end
  self.Auth = bool
  return true
end

function WebSession:isAuth(req)
  if self.Auth == req.session[req.cookies.sID].isAuth then
    return true end
  return false
end

function WebSession:destroy(req, res)
  
  local sid = req.cookies.sID
  req.session = {}
  req.session[sid] = {}
  req.session[sid].user = nil
  req.session[sid].isAuth = false

  self.SessionID = nil
  self.Auth = nil
  
  res.clearCookie("sID")
end

return WebSession
