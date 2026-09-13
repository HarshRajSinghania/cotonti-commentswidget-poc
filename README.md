# Cotonti CommentsWidget PHP Object Injection PoC

Safe local proof of concept for the PHP object injection issue identified in Cotonti's CommentsWidget implementation.

## Vulnerability

- **Project:** Cotonti
- **Affected component:** `plugins/comments/inc/CommentsWidget.php`
- **CWE:** CWE-502 — Deserialization of Untrusted Data
- **CVE/Candidate:** CAN-2026-2035973 / CVE-2026-71294
- **Researcher:** Harsh Raj Singhania

The vulnerable code path accepts the `ci` GET parameter and passes attacker-controlled data through `base64_decode()` into PHP's `unserialize()` without restricting which classes may be instantiated.

Conceptually, the vulnerable operation is:

```php
$ci = @unserialize(base64_decode($ci));
```

When a serialized object is supplied, PHP may instantiate the attacker-controlled class and invoke magic methods such as `__wakeup()`. In a larger application this can become dangerous when suitable gadget classes are available.

The submitted fix changes deserialization to:

```php
$ci = @unserialize(base64_decode($ci), ['allowed_classes' => false]);
```

and validates that the resulting value has the expected array structure before using it.

## What this PoC demonstrates

`poc.php` performs three local tests:

1. **Vulnerable behavior** — unrestricted `unserialize()` instantiates `DangerousGadget` and triggers its `__wakeup()` method.
2. **Fixed behavior** — `allowed_classes => false` prevents the gadget class from being instantiated and therefore prevents the `__wakeup()` side effect.
3. **Structural validation** — a serialized value with an unexpected shape is rejected by the validation logic used by the fix.

The PoC uses `/tmp/pwned_by_cotonti_poc.txt` only as a harmless sentinel showing that `__wakeup()` executed. It does **not** execute an operating-system command. The `id && whoami` string exists only as a placeholder value in the gadget's `command` property.

## Requirements

- PHP CLI with `serialize()` / `unserialize()` support
- A local test environment

No Cotonti installation is required because the vulnerable and fixed deserialization behavior is reproduced directly.

## Running the PoC

From the repository directory:

```bash
php poc.php
```

Expected output is similar to:

```text
[!] DangerousGadget::__wakeup() triggered
[TEST 1] VULNERABLE: __wakeup() executed during unrestricted unserialize().
[TEST 2] FIXED: object instantiation was blocked; no sentinel was created.
[TEST 3] FIXED: invalid serialized structure rejected by validation.

Summary:
- Vulnerable path allows a serialized attacker-controlled object to be instantiated and invokes __wakeup().
- Fixed path uses allowed_classes=false, preventing the gadget class from being instantiated.
- Structural validation rejects values that do not match the expected array shape.
- No real command execution is performed by this PoC; the command property is only a placeholder.
```

The script removes its sentinel file before exiting.

## Remediation

Do not deserialize attacker-controlled data with unrestricted PHP `unserialize()`.

For this code path, the demonstrated mitigation is to disable class instantiation:

```php
unserialize($data, ['allowed_classes' => false]);
```

The deserialized value should also be validated against the exact structure expected by the application before its contents are used.

## References

- Upstream security issue: https://github.com/Cotonti/Cotonti/issues/1888
- Upstream fix pull request: https://github.com/Cotonti/Cotonti/pull/1889
- Cotonti project: https://github.com/Cotonti/Cotonti

## Responsible use

This repository is intended for security research, verification, and defensive testing. Run the PoC only in environments you own or are explicitly authorized to test. Do not use it to target systems without permission.

## Attribution

**Harsh Raj Singhania** — vulnerability research, proof of concept, and disclosure.
