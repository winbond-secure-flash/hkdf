
#ifndef __KEY_STREAM_H__
#define __KEY_STREAM_H__

#include "hkdf.h"

#ifdef __cplusplus
extern "C" {
#endif
    
    typedef struct _hkdf_key_material
    {
        void* ikm;
        size_t ikm_size;
        void* salt;
        size_t salt_size;
    } HKDF_KEY_MATERIAL;

    typedef struct _hkdf_descriptor
    {
        HKDF_KEY_MATERIAL key_material;
        void* keys_buffer;
        int keys_num;
        size_t key_size;
    } HKDF_KSTREAM;

    // salt is secret, ikm is key identifier     
    int kstream_init_material(HKDF_KSTREAM* stream, void* key_id, size_t key_id_size, void* secret, size_t secret_size);

    // allocs memory for keys_buffer, keys_num is number of keys to generate, key_size is size of each key
    int kstream_alloc(HKDF_KSTREAM* stream, size_t key_size, int keys_num);

    // finds the key at key_index and copies it to key
    int kstream_get_key(HKDF_KSTREAM* stream, int key_index, void* key, size_t key_size);

    // frees the keys_buffer and resets the stream key material   
    int kstream_free(HKDF_KSTREAM* stream);

#ifdef __cplusplus
}
#endif

#endif // __KEY_STREAM_H__
