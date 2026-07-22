# HKDF-based key stream reference implementation



⚠️ This implementation is provided **strictly for rapid prototyping, testing, and initial customer integration**. It is **not** an official part of the product release and will not be updated.



## Purpose & Intended Use

To help you get up and running with our crypto product as quickly as possible, we have included this standalone HKDF implementation. It allows you to validate your end-to-end data pipelines and flows work without needing to immediately configure the maintained crypto library for this.


These are the code examples given in the IETF RFC6234:
  http://tools.ietf.org/html/rfc6234

## Production Requirements


We strongly recommend replacing this reference module with source that meets the following criteria:

1. **DPA Protection:** Use implementation that includes explicit countermeasures against Differential Power Analysis (DPA).
 
2. **Well Maintened:** Source your cryptographic primitives from actively maintained, rigorously audited libraries to ensure continuous protection against newly discovered vulnerabilities.


## Key stream core API ( `key_stream.h` )

```c
int kstream_init(HKDF_KSTREAM* stream, const void* id, size_t id_size, const void* secret, size_t secret_size);

```

Initializes the key stream context with key material.

* **`stream`**: Pointer to the `HKDF_KSTREAM` structure to initialize.
* **`id`**: Pointer to the key identifier (used as `ikm`).
* **`id_size`**: Size of the identifier in bytes.
* **`secret`**: Pointer to the secret keying material (used as `salt`).
* **`secret_size`**: Size of the secret in bytes.
* **Returns**: Status code (`0` for success, non-zero for failure).

---

```c
int kstream_alloc(HKDF_KSTREAM* stream, size_t key_size, int keys_num);

```

Allocates memory for `keys_buffer` and derives the specified number of keys based on the initialized key material.

* **`stream`**: Pointer to an initialized `HKDF_KSTREAM` structure.
* **`key_size`**: Desired byte length for each derived key.
* **`keys_num`**: Number of keys to derive.
* **Returns**: Status code (`0` for success, non-zero for failure).

---

```c
int kstream_get_key(HKDF_KSTREAM* stream, int key_index, void* key, size_t key_size);

```

Retrieves a specific derived key from the internal buffer and copies it into the caller's buffer.

* **`stream`**: Pointer to the `HKDF_KSTREAM` structure.
* **`key_index`**: Zero-based index of the key to retrieve (`0` to `keys_num - 1`).
* **`key`**: Output buffer to store the retrieved key.
* **`key_size`**: Expected size of the destination buffer (must match `stream->key_size`).
* **Returns**: Status code (`0` for success, non-zero for failure/out-of-bounds).

---

```c
int kstream_free(HKDF_KSTREAM* stream);

```

Frees allocated memory for `keys_buffer` and clears the key material parameters in the stream context.

* **`stream`**: Pointer to the `HKDF_KSTREAM` structure to clean up.
* **Returns**: Status code (`0` for success, non-zero for failure).

---

## Usage Example

```c
#include <stdio.h>
#include <string.h>
#include "key_stream.h"

int main(void) {
    HKDF_KSTREAM stream;
    
    const char secret[] = "super_secret_master_salt";
    const char id[] = "session_id_12345";
    
    // 1. Initialize the stream context
    if (kstream_init(&stream, id, strlen(id), secret, strlen(secret)) != 0) {
        fprintf(stderr, "Failed to initialize key stream.\n");
        return -1;
    }

    // 2. Allocate and derive 5 keys of 32 bytes each
    size_t key_len = 32;
    int num_keys = 5;
    if (kstream_alloc(&stream, key_len, num_keys) != 0) {
        fprintf(stderr, "Failed to allocate key buffer.\n");
        return -1;
    }

    // 3. Fetch key at index 2
    unsigned char key_out[32];
    if (kstream_get_key(&stream, 2, key_out, sizeof(key_out)) == 0) {
        printf("Key 2 retrieved successfully!\n");
    }

    // 4. Free resources
    kstream_free(&stream);
    return 0;
}

```


## Usage Example For W77Q Key Generation

```c

// qlib definitions are needed for this w77q_hkdf usage
#include "qlib.h"
#include "key-stream.h"


#ifdef __cplusplus
extern "C" {
#endif


// the layout of all keys in hkdf output will be: 
// 0     - dev. master key   |
// 1 - 9 - full access 0 key | full access 1 key | full access 2 ......| full access 7 key |full access 8 key |
// 10     - dev. secret key  |
// 11-19 - restricted  0 key | restricted  1 key | restricted  2 ......| restricted  7 key |restricted  8 key |
enum
{
    KSTREAM_IDX_DEVICE_MASTER_KEY,                                                          //0
    KSTREAM_IDX_FULL_ACCESS_SECTION_0,                                                      //1...9
    KSTREAM_IDX_DEVICE_SECRET = KSTREAM_IDX_FULL_ACCESS_SECTION_0 + QLIB_NUM_OF_SECTIONS,   //10
    KSTREAM_IDX_RESTRICTED_ACCESS_SECTION_0,                                                //11...19
    KSTREAM_KEYS_NUM = KSTREAM_IDX_RESTRICTED_ACCESS_SECTION_0 + QLIB_NUM_OF_SECTIONS,      //20
};

#define KEYTYPE_TO_IDX_SINGLE_DIE(type, sec)                                                                    \
       (type == QLIB_KID__DEVICE_MASTER             ?   KSTREAM_IDX_DEVICE_MASTER_KEY                       :   \
        type == QLIB_KID__FULL_ACCESS_SECTION       ?   (KSTREAM_IDX_FULL_ACCESS_SECTION_0 + (sec))         :   \
        type == QLIB_KID__DEVICE_SECRET             ?   KSTREAM_IDX_DEVICE_SECRET                           :   \
        type == QLIB_KID__RESTRICTED_ACCESS_SECTION ?   (KSTREAM_IDX_RESTRICTED_ACCESS_SECTION_0 + (sec))   :   \
        -KSTREAM_KEYS_NUM) // -KSTREAM_KEYS_NUM is invalid value   

#define KEYTYPE_TO_IDX(type, sec, die) ((KSTREAM_KEYS_NUM * die) + KEYTYPE_TO_IDX_SINGLE_DIE(type, sec))  

inline QLIB_STATUS_T w77q_kstream_init(HKDF_KSTREAM *kstr, const QLIB_WID_T wid, const KEY_T secret)
{
    return  kstream_init(kstr, wid, sizeof(QLIB_WID_T), secret, sizeof(KEY_T)) ? QLIB_STATUS__COMMAND_FAIL : QLIB_STATUS__OK;
}

inline QLIB_STATUS_T w77q_kstream_alloc(HKDF_KSTREAM *kstr, uint32_t numOfDies)
{
    return  kstream_alloc(kstr, sizeof(KEY_T), KSTREAM_KEYS_NUM * numOfDies) ? QLIB_STATUS__COMMAND_FAIL : QLIB_STATUS__OK;    
}

inline QLIB_STATUS_T w77q_kstream_get_key(HKDF_KSTREAM *kstr, const QLIB_KID_TYPE_T type, uint32_t sect,  uint32_t die, KEY_T key)
{
    int keyIdx = KEYTYPE_TO_IDX(type, sect, die);
    return  kstream_get_key(kstr, keyIdx, key, sizeof(KEY_T)) ? QLIB_STATUS__COMMAND_FAIL : QLIB_STATUS__OK; 
}

inline  QLIB_STATUS_T w77q_kstream_free(HKDF_KSTREAM * kstr)
{    
    return  kstream_free(kstr) ? QLIB_STATUS__COMMAND_FAIL : QLIB_STATUS__OK;
}

QLIB_STATUS_T w77q_kstream_sample(KEY_T cmk, QLIB_WID_T wid)
{
    
    HKDF_KSTREAM kstr;
    
    QLIB_STATUS_RET_CHECK(w77q_kstream_init(&kstr, wid, cmk));
    QLIB_STATUS_RET_CHECK(w77q_kstream_alloc(&kstr, 1));

    // getting full access section zero die zero key 
    KEY_T fullAccessSectionZero; 
    QLIB_STATUS_RET_CHECK(w77q_kstream_get_key(&kstr, QLIB_KID__FULL_ACCESS_SECTION, 0, 0, fullAccessSectionZero));

    // getting restricted access section two die zero key 
    KEY_T restrictedAccessSectionTwo; 
    QLIB_STATUS_RET_CHECK(w77q_kstream_get_key(&kstr, QLIB_KID__RESTRICTED_ACCESS_SECTION, 2, 0, restrictedAccessSectionTwo));

    // getting device master key (section and die number are ignored), since it is common to all dies 
    KEY_T deviceMaster; 
    QLIB_STATUS_RET_CHECK(w77q_kstream_get_key(&kstr, QLIB_KID__DEVICE_MASTER, 0, 0, deviceMaster));

    // getting vault ( which is section 9 ) full access key, die zero 
    KEY_T fullAccessVault;
    QLIB_STATUS_RET_CHECK(w77q_kstream_get_key(&kstr, QLIB_KID__FULL_ACCESS_SECTION, 8, 0, fullAccessVault));

    QLIB_STATUS_RET_CHECK(w77q_kstream_free(&kstr));

    // Now you can use the keys to open secure session, configure etc...
    
    
    return QLIB_STATUS__OK;
}

```
