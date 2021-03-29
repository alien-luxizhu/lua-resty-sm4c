-- Copyright (C) by luxizhu
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_gc = ffi.gc
local ffi_str = ffi.string
local ffi_copy = ffi.copy
--local C = ffi.load(ffi.abi'win' and 'libcrypto' or 'crypto')
local C = ffi.C
local setmetatable = setmetatable
local type = type

---@class sm4c
local _M = { _VERSION = '0.12' }

local mt = { __index = _M }

-- https://www.openssl.org/docs/manmaster/man3/
ffi.cdef [[
typedef struct engine_st ENGINE;

typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

typedef struct env_md_ctx_st EVP_MD_CTX;
typedef struct env_md_st EVP_MD;

const EVP_MD *EVP_md5(void);
const EVP_MD *EVP_sha(void);
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_sha224(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);

const EVP_CIPHER *EVP_sm4_ecb(void);
const EVP_CIPHER *EVP_sm4_cbc(void);
const EVP_CIPHER *EVP_sm4_cfb128(void);

int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int);

EVP_CIPHER_CTX *EVP_CIPHER_CTX_new();
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *a);

int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher,
        ENGINE *impl, unsigned char *key, const unsigned char *iv);

int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
        const unsigned char *in, int inl);

int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher,
        ENGINE *impl, unsigned char *key, const unsigned char *iv);

int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
        const unsigned char *in, int inl);

int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

int EVP_BytesToKey(const EVP_CIPHER *type,const EVP_MD *md,
        const unsigned char *salt, const unsigned char *data, int datal,
        int count, unsigned char *key,unsigned char *iv);
]]

--in file openssl/evp.h
local padding = {
    EVP_CIPH_NO_PADDING = 0,
    EVP_PADDING_PKCS7 = 1,
    EVP_PADDING_ISO7816_4 = 2,
    EVP_PADDING_ANSI923 = 3,
    EVP_PADDING_ISO10126 = 4,
    EVP_PADDING_ZERO = 5,
}

local hash = {
    md5 = C.EVP_md5(),
    sha1 = C.EVP_sha1(),
    sha224 = C.EVP_sha224(),
    sha256 = C.EVP_sha256(),
    sha384 = C.EVP_sha384(),
    sha512 = C.EVP_sha512()
}
_M.hash = hash
_M.padding = padding

---@param sm4_mode "ecb"|"cbc"|"cfb128"
---@return { cipher: string, method: function }
local cipher = function(sm4_mode)
    local _cipher = sm4_mode or "ecb"
    local func = "EVP_sm4_" .. _cipher
    if C[func] then
        return { cipher = _cipher, method = C[func]() }
    else
        return nil
    end
end
_M.cipher = cipher

local evp = {}
function evp.encrypt(ctx, s)
    local s_len = #s
    local max_len = s_len + 16
    local buf = ffi_new("unsigned char[?]", max_len)
    local out_len = ffi_new("int[1]")
    local tmp_len = ffi_new("int[1]")

    if C.EVP_EncryptInit_ex(ctx, nil, nil, nil, nil) == 0 then
        return nil
    end

    if C.EVP_EncryptUpdate(ctx, buf, out_len, s, s_len) == 0 then
        return nil
    end

    if C.EVP_EncryptFinal_ex(ctx, buf + out_len[0], tmp_len) == 0 then
        return nil
    end

    return ffi_str(buf, out_len[0] + tmp_len[0])
end

function evp.decrypt(ctx, s)
    local s_len = #s
    local buf = ffi_new("unsigned char[?]", s_len)
    local out_len = ffi_new("int[1]")
    local tmp_len = ffi_new("int[1]")

    if C.EVP_DecryptInit_ex(ctx, nil, nil, nil, nil) == 0 then
        return nil
    end

    if C.EVP_DecryptUpdate(ctx, buf, out_len, s, s_len) == 0 then
        return nil
    end

    if C.EVP_DecryptFinal_ex(ctx, buf + out_len[0], tmp_len) == 0 then
        return nil
    end

    return ffi_str(buf, out_len[0] + tmp_len[0])
end

function evp.set_padding(ctx, value)
    return C.EVP_CIPHER_CTX_set_padding(ctx, value)
end

function _M.new(key, salt, _cipher, _hash, hash_rounds)
    _cipher = _cipher or cipher()
    _hash = _hash or hash.md5
    hash_rounds = hash_rounds or 1
    local _cipherLength = 16
    local gen_key = ffi_new("unsigned char[?]", _cipherLength)
    local gen_iv = ffi_new("unsigned char[?]", 8)

    if type(_hash) == "table" then
        if not _hash.iv or #_hash.iv < 8 then
            return nil, "bad iv"
        end

        if _hash.method then
            local tmp_key = _hash.method(key)

            if #tmp_key ~= _cipherLength then
                return nil, "bad key length"
            end

            ffi_copy(gen_key, tmp_key, _cipherLength)

        elseif #key ~= _cipherLength then
            return nil, "bad key length"

        else
            ffi_copy(gen_key, key, _cipherLength)
        end

        ffi_copy(gen_iv, _hash.iv, 8)

    else
        if salt and #salt ~= 8 then
            return nil, "salt must be 8 characters or nil"
        end

        if C.EVP_BytesToKey(_cipher.method, _hash, salt, key, #key,
                hash_rounds, gen_key, gen_iv)
                ~= _cipherLength
        then
            return nil
        end
    end

    local encrypt_ctx = C.EVP_CIPHER_CTX_new()
    if encrypt_ctx == nil then
        return nil, "no memory"
    end
    ffi_gc(encrypt_ctx, C.EVP_CIPHER_CTX_free)
    if C.EVP_EncryptInit_ex(encrypt_ctx, _cipher.method, nil,
            gen_key, gen_iv) == 0 then
        return nil, "EVP_EncryptInit_ex error"
    end

    local decrypt_ctx = C.EVP_CIPHER_CTX_new()
    if decrypt_ctx == nil then
        return nil, "no memory"
    end

    ffi_gc(decrypt_ctx, C.EVP_CIPHER_CTX_free)
    if C.EVP_DecryptInit_ex(decrypt_ctx, _cipher.method, nil,
            gen_key, gen_iv) == 0 then
        return nil, "EVP_DecryptInit_ex error"
    end

    return setmetatable({
        _encrypt_ctx = encrypt_ctx,
        _decrypt_ctx = decrypt_ctx
    }, mt)
end

function _M:set_padding(value)
    evp.set_padding(self._encrypt_ctx, value)
    evp.set_padding(self._decrypt_ctx, value)
    return self
end

function _M.encrypt(self, s)
    return evp.encrypt(self._encrypt_ctx, s)
end

function _M.decrypt(self, s)
    return evp.decrypt(self._decrypt_ctx, s)
end

return _M

