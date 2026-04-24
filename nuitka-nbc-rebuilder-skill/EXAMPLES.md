# NBC -> Python Reconstruction Examples

These examples show the reconstruction policy. The goal is maximum fidelity
from evidence, not confident guessing.

## Example 1 - Evidenced Constants and HTTP Shape

Input excerpt:

```text
@MOD modules.balance.bitcoin
@CONSTS 10 mode=full_repr
  0 i 100000000
  1 s 'https://blockchain.info/balance?active='
  2 s 'session'
  3 s 'get'
  4 s 'status_code'
  5 i 200
  6 s 'json'
  7 s 'final_balance'
  8 s 'Request failed with status code: '
  9 T ('address', 'url', 'response')

@FUNCS_DETECTED
  fetch_from_blockchain(address, url, response)

@OPS 0x1000 # fetch_from_blockchain
  L c[1]
  C r#0
  C r#0
  C r#2
  L c[4]
  C r#0
  J_NE c[5] L1
  L c[6]
  C r#0
  C r#1
  L c[7]
  C r#0
  L c[0]
  RET
  :L1
  L c[8]
  RET
```

Acceptable output:

```python
# MODULE: modules.balance.bitcoin
# CONFIDENCE: 80% evidence-backed reconstruction
# UNCERTAIN SPANS: 1

def fetch_from_blockchain(address, url, response):
    url = 'https://blockchain.info/balance?active=' + address
    response = session.get(url)
    if response.status_code == 200:
        return response.json()['final_balance'] / 100000000
    # UNCERTAIN: failure branch loads the error string but the exact print/return path is not fully evidenced
    return 'Request failed with status code: '
```

Why: every literal is taken from `@CONSTS`; the uncertain branch is marked
instead of inventing a print call.

## Example 2 - Missing Body

Input excerpt:

```text
@FUNCS_DETECTED
  hmac_sign(data)

@FORENSICS 1
@NO_OPS hmac_sign
  qualname_idx: 12
  adjacent:
    c[10] s 'hmac_sign'
    c[11] T ('data',)
    c[12] s 'hmac_sign'
```

Correct output:

```python
# MODULE: unknown
# CONFIDENCE: 20% evidence-backed reconstruction
# UNCERTAIN SPANS: 1

def hmac_sign(data):
    # UNCERTAIN: body not reached by @OPS; forensics contain only the name and args
    ...
```

Wrong output:

```python
def hmac_sign(data):
    return hmac.new(KEY, data, hashlib.sha256).hexdigest()
```

The wrong output invents key material, imports, and algorithm choices.

## Example 3 - Import Chain

Input excerpt:

```text
@IMPORTS
  from colorama import Fore, Style

@OPS 0x2000
  L c[0]
  C capi:PyImport_ImportModule
  L c[1]
  C capi:PyObject_GetAttrString
  L c[2]
  C capi:PyObject_GetAttrString

@CONSTS 3 mode=full_repr
  0 s 'colorama'
  1 s 'Fore'
  2 s 'Style'
```

Correct output:

```python
# MODULE: unknown
# CONFIDENCE: 95% evidence-backed reconstruction
# UNCERTAIN SPANS: 0

from colorama import Fore, Style
```

## Example 4 - Truncated NBC

Input:

```text
@MOD sample
@CONSTS 0
@NO_OPS
```

Correct behavior:

```text
The `.nbc` has no constants and no operation evidence. Please provide the full
NBC/2 file from `AI_READY_NBC/nbc/`; otherwise the source would be fabricated.
```

## Example 5 - Native ASM Resolves an Ambiguity

Input excerpt:

```text
@CONSTS 4 mode=full_repr
  0 s 'config'
  1 s 'get'
  2 s 'saveLogs'
  3 F False

@OPS 0x3000 # loadConfig
  L c[0]
  C r#0
  L c[1]
  C r#0
  L c[2]
  C r#2
  RET

@ASM 0x3000
  0x3001: mov rcx, qword ptr [...] ; const c[0]='config'
  0x3008: call ... ; LOOKUP_ATTRIBUTE
  0x3010: mov rcx, qword ptr [...] ; const c[1]='get'
  0x3018: call ... ; LOOKUP_ATTRIBUTE
  0x3020: mov rcx, qword ptr [...] ; const c[2]='saveLogs'
  0x3028: call ... ; CALL_FUNCTION_WITH_ARGS1
```

Acceptable output:

```python
# MODULE: unknown
# CONFIDENCE: 75% evidence-backed reconstruction
# UNCERTAIN SPANS: 1

def loadConfig():
    # UNCERTAIN: receiver object for config.get is inferred from attribute sequence, not explicitly named
    return config.get('saveLogs')
```
