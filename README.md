# lua-resty-sm4c

## zero padding test

```
local key = "16 bytes ...."
local sm4iv = string.rep("0", 16)
local sm4 = require('util.sm4c')
local str = require "resty.string"

local function gen_key16(k)
    return string.sub(k, 1, 16)
end

local hash = { iv = sm4iv, method = gen_key16 }
local cipher = sm4.cipher("ecb")
local sm4_ecb = sm4.new(key, nil, cipher, hash)
sm4_ecb:set_padding(sm4.padding.EVP_CIPH_NO_PADDING)

local function ZeroPadding(s, nBlockSize)
    local nLen = #s
    local paddingCount = nBlockSize - nLen % nBlockSize
    return s .. string.rep("\0", paddingCount)
end

local function c_str(s)
    for i = 1, #s do
        if string.byte(s, i) == 0 then
            return string.sub(s, 1, i - 1)
        end
    end
    return s
end

local text = "I love you. But it's a secret."
print("text = ", text, "#", #text)

local crypted = sm4_ecb:encrypt(ZeroPadding(text, 16))

ngx.say('sm4_ecb Encryption with zero padding')
ngx.say('  HEX: ' .. str.to_hex(crypted))
ngx.say('  Base64: ' .. ngx.encode_base64(crypted))

ngx.say('\nsm4_ecb Decryption')
local xx = sm4_ecb:decrypt(crypted)
xx = c_str(xx)
ngx.say(xx)

```
