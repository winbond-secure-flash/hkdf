#include "key-stream.h"
#include <string.h>
#include <stdlib.h>

int kstream_init_material(HKDF_KSTREAM* stream, void* key_id, size_t key_id_size, void* secret, size_t secret_size)
{
    if (!stream || !key_id || !secret)
        return -1;

    memset(stream, 0, sizeof(HKDF_KSTREAM));
    stream->key_material.ikm = key_id;
    stream->key_material.ikm_size = key_id_size;
    stream->key_material.salt = secret;
    stream->key_material.salt_size = secret_size;

    return 0;
}

int kstream_alloc(HKDF_KSTREAM* stream, size_t key_size, size_t keys_num)
{
    if (!stream || key_size == 0 || keys_num == 0)
        return -1;

    size_t total_size = key_size * keys_num;
    stream->keys_buffer = malloc(total_size);
    if (!stream->keys_buffer)
        return -1;

    stream->key_size = key_size;
    stream->keys_num = keys_num;

    // Use HKDF to derive the entire key stream in one call
    // salt is the secret, ikm is the key identifier
    int ret = hkdf(SHA256,
        (const unsigned char*)stream->key_material.salt, (int)stream->key_material.salt_size,
        (const unsigned char*)stream->key_material.ikm, (int)stream->key_material.ikm_size,
        NULL, 0,
        (uint8_t*)stream->keys_buffer, (int)total_size);

    if (ret != shaSuccess)
    {
        free(stream->keys_buffer);
        stream->keys_buffer = NULL;
        return -1;
    }

    return 0;
}

int kstream_get_key(HKDF_KSTREAM* stream, int key_index, void* key, size_t key_size)
{
    if (!stream || !key || !stream->keys_buffer)
        return -1;

    if (key_index < 0 || key_index >= stream->keys_num)
        return -1;

    if (key_size < stream->key_size)
        return -1;

    unsigned char* src = (unsigned char*)stream->keys_buffer + (key_index * stream->key_size);
    memcpy(key, src, stream->key_size);

    return 0;
}

int kstream_free(HKDF_KSTREAM* stream)
{
    if (!stream)
        return -1;

    if (stream->keys_buffer)
    {
        // Zero out key material before freeing for security
        memset(stream->keys_buffer, 0, stream->key_size * stream->keys_num);
        free(stream->keys_buffer);
    }

    memset(stream, 0, sizeof(HKDF_KSTREAM));

    return 0;
}