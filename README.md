# HKDF Integration Reference Implementation



⚠️ This implementation is provided **strictly for rapid prototyping, testing, and initial customer integration**. It is **not** an official part of the product release and will not be updated.



## Purpose & Intended Use

To help you get up and running with our crypto product as quickly as possible, we have included this standalone HKDF implementation. It allows you to validate your end-to-end data pipelines and flows work without needing to immediately configure the maintained crypto library for this.


These are the code examples given in the IETF RFC6234:
  http://tools.ietf.org/html/rfc6234


## How W77Q Key Derivation works

All W77Q chip keys are derived using HKDF with SHA-256. The two inputs are:

- **Secret** – A 128-bit OEM secret key provided by the user
- **WID** – The unique Winbond chip ID read from the chip

HKDF uses the secret as input keying material (**IKM**) and the **WID** as salt to produce a deterministic key stream. Each 128-bit chunk of the output maps to a specific key according to the following layout (per die):

| Offset | Key |
|--------|-----|
| 0 | Device Master Key |
| 1–8 | Full Access Section 0–7 Keys |
| 9 | Full Access Vault Key (Section 8) |
| 10 | Device Secret Key |
| 11–18 | Restricted Access Section 0–7 Keys |
| 19 | Restricted Access Vault Key (Section 8) |

For multi-die configurations the layout repeats per die, offset by `HKDF_W77Q_KEYS_NUM * die`.

The same secret and WID always produce the same keys, while a different WID yields a completely different key set. OEM can change how key stream is cut into keys of course.

## HKDF Core API

The underlying HKDF primitive used by this module, returns `0` on success.:

```c
int hkdf(  SHAversion whichSha,
           const unsigned char *salt, int salt_len,
           const unsigned char *ikm, int ikm_len,
           const unsigned char *info, int info_len,
           uint8_t okm[], int okm_len)
```



| Parameter | Description |
|-----------|-------------|
| `whichSha` | Hash algorithm to use (this module uses `SHA256`) |
| `salt` | Salt value — the chip **WID** |
| `salt_len` | Length of the salt (`sizeof(QLIB_WID_T)`) |
| `ikm` | Input keying material — the OEM **Secret** |
| `ikm_len` | Length of the IKM (`sizeof(KEY_T)`) |
| `info` | Optional context/application info (unused, passed as `NULL`) |
| `info_len` | Length of info (passed as `0`) |
| `okm` | Output buffer for the derived key stream |
| `okm_len` | Output length (`sizeof(KEY_T) * keys num * dies num`) |
