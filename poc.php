<?php
/**
 * Cotonti CommentsWidget PHP Object Injection - Safe Local PoC
 *
 * This PoC demonstrates the difference between unrestricted PHP unserialize()
 * and the fixed allowed_classes=false behavior. It does NOT execute a real
 * operating-system command.
 */

final class DangerousGadget
{
    public string $command = 'id && whoami';

    public function __wakeup(): void
    {
        $sentinel = '/tmp/pwned_by_cotonti_poc.txt';
        file_put_contents($sentinel, "__wakeup__ was triggered\n", LOCK_EX);
        echo "[!] DangerousGadget::__wakeup() triggered\n";
    }
}

function makePayload(): string
{
    $object = new DangerousGadget();
    return base64_encode(serialize($object));
}

function simulateCotImport(string $ci): string
{
    return trim(strip_tags($ci));
}

function cleanupSentinel(): void
{
    @unlink('/tmp/pwned_by_cotonti_poc.txt');
}

function sentinelExists(): bool
{
    return file_exists('/tmp/pwned_by_cotonti_poc.txt');
}

$ci = simulateCotImport(makePayload());

// Test 1: Vulnerable behavior - unrestricted unserialize().
cleanupSentinel();
$vulnerable = @unserialize(base64_decode($ci));

if (sentinelExists()) {
    echo "[TEST 1] VULNERABLE: __wakeup() executed during unrestricted unserialize().\n";
} else {
    echo "[TEST 1] Unexpected: sentinel was not created.\n";
}

// Test 2: Fixed behavior - disallow object instantiation.
cleanupSentinel();
$fixed = @unserialize(base64_decode($ci), ['allowed_classes' => false]);

if (!sentinelExists() && $fixed instanceof __PHP_Incomplete_Class) {
    echo "[TEST 2] FIXED: object instantiation was blocked; no sentinel was created.\n";
} elseif (!sentinelExists()) {
    echo "[TEST 2] FIXED: no gadget side effect occurred.\n";
} else {
    echo "[TEST 2] FAILED: sentinel was created.\n";
}

// Test 3: Structural validation expected by the fix.
$badShape = base64_encode(serialize('unexpected scalar'));
$decoded = @unserialize(base64_decode($badShape), ['allowed_classes' => false]);

if (
    !is_array($decoded) ||
    !isset($decoded[0], $decoded[1]) ||
    !is_string($decoded[0]) ||
    !is_array($decoded[1])
) {
    echo "[TEST 3] FIXED: invalid serialized structure rejected by validation.\n";
} else {
    echo "[TEST 3] FAILED: invalid structure was accepted.\n";
}

cleanupSentinel();

echo "\nSummary:\n";
echo "- Vulnerable path allows a serialized attacker-controlled object to be instantiated and invokes __wakeup().\n";
echo "- Fixed path uses allowed_classes=false, preventing the gadget class from being instantiated.\n";
echo "- Structural validation rejects values that do not match the expected array shape.\n";
echo "- No real command execution is performed by this PoC; the command property is only a placeholder.\n";
