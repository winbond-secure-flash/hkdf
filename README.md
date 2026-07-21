# HKDF Integration Reference Implementation



⚠️ This implementation is provided **strictly for rapid prototyping, testing, and initial customer integration**. It is **not** an official part of the product release and will not be updated.



## Purpose & Intended Use

To help you get up and running with our crypto product as quickly as possible, we have included this standalone HKDF implementation. It allows you to validate your end-to-end data pipelines and flows work without needing to immediately configure the maintained crypto library for this.


These are the code examples given in the IETF RFC6234:
  http://tools.ietf.org/html/rfc6234

## Production Requirements


We strongly recommend replacing this reference module with source that meets the following criteria:

1. **DPA Protection:** Use implementation that includes explicit countermeasures against Differential Power Analysis (DPA).
 
2. **Well Maintened:** Source your cryptographic primitives from actively maintained, rigorously audited libraries to ensure continuous protection against newly discovered vulnerabilities.



## Key Stream API

The key-stream module wraps HKDF to provide indexed access to derived keys. All functions return `0` on success.

### Types

### Functions

#### `kstream_init_material`

Initializes key material. Salt is the secret, IKM is the key identifier.

#### `kstream_alloc`

Allocates the key buffer and derives `keys_num` keys of `key_size` bytes each using HKDF-SHA256.

#### `kstream_get_key`

Copies the key at `key_index` into the caller-provided buffer.

#### `kstream_free`

Zeroes all key material (keys buffer, IKM, salt) and frees allocated memory.


## Example How key stream can work for W77Q Key Derivation

- **Secret** – A 128-bit OEM secret key provided by the user
- **WID** – The unique Winbond chip ID read from the chip

Key stream will use the secret as input keying material (**IKM**) and the **WID** as salt to produce
a deterministic key stream. Each 128-bit chunk of the output maps to a specific key
according to the following **offset mapping** ( oem can change it according to his requirements) layout:

| Offset | Key |
|--------|-----|
| 0 | Device Master Key |
| 1–8 | Full Access Section 0–7 Keys |
| 9 | Full Access Vault Key (Section 8) |
| 10 | Device Secret Key |
| 11–18 | Restricted Access Section 0–7 Keys |
| 19 | Restricted Access Vault Key (Section 8) |

The same secret and WID always produce the same keys, while a different WID yields a completely different key set. OEM can change how key stream is cut into keys of course.
