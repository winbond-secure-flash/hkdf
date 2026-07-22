#include "key-stream.h"
#include <string.h>
#include <stdlib.h>

int kstream_init(HKDF_KSTREAM* kstr, const void* id, size_t id_size, const void* secret, size_t secret_size)
{
    if (!kstr || !id || !secret)
        return -1;

    memset(kstr, 0, sizeof(HKDF_KSTREAM));
    kstr->key_material.ikm = id;
    kstr->key_material.ikm_size = id_size;
    kstr->key_material.salt = secret;
    kstr->key_material.salt_size = secret_size;

    return 0;
}

int kstream_alloc(HKDF_KSTREAM* kstr, size_t key_size, int keys_num)
{
    if (!kstr || key_size == 0 || keys_num <= 0)
        return -1;

    size_t total_size = key_size * keys_num;
    kstr->keys_buffer = malloc(total_size);
    if (!kstr->keys_buffer)
        return -1;

    kstr->key_size = key_size;
    kstr->keys_num = keys_num;

    // Use HKDF to derive the entire key kstr in one call
    // salt is the secret, ikm is the key identifier
    int ret = hkdf(SHA256,
        (const unsigned char*)kstr->key_material.salt, (int)kstr->key_material.salt_size,
        (const unsigned char*)kstr->key_material.ikm, (int)kstr->key_material.ikm_size,
        NULL, 0,
        (uint8_t*)kstr->keys_buffer, (int)total_size);

    if (ret != shaSuccess)
    {
        free(kstr->keys_buffer);
        kstr->keys_buffer = NULL;
        return -1;
    }

    return 0;
}

int kstream_get_key(HKDF_KSTREAM* kstr, int key_index, void* key, size_t key_size)
{
    if (!kstr || !key || !kstr->keys_buffer)
        return -1;

    if (key_index < 0 || key_index >= kstr->keys_num)
        return -1;

    if (key_size != kstr->key_size)
        return -1;

    unsigned char* src = (unsigned char*)kstr->keys_buffer + (key_index * kstr->key_size);
    memcpy(key, src, kstr->key_size);

    return 0;
}

int kstream_free(HKDF_KSTREAM* kstr)
{
    if (!kstr)
        return -1;

    if (kstr->keys_buffer)
    {
        // Zero out keys before freeing
        memset(kstr->keys_buffer, 0, kstr->key_size * kstr->keys_num);
        free(kstr->keys_buffer);
    }

    memset(kstr, 0, sizeof(HKDF_KSTREAM));
    return 0;
}