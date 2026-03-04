<?php

declare(strict_types=1);

namespace OCA\CapAuth\Service;

use OCP\ILogger;

/**
 * Verifies PGP signatures produced by CapAuth clients.
 *
 * Uses the PHP gnupg extension when available; falls back to shelling out
 * to gpg2/gpg via proc_open for environments where the extension is absent.
 */
class VerifierService {
    public function __construct(
        private readonly ILogger $logger,
    ) {}

    // ── Canonical payload builders ───────────────────────────────────────────

    public function canonicalNoncePayload(
        string $nonce,
        string $clientNonce,
        string $issuedAt,
        string $service,
        string $expiresAt,
    ): string {
        return implode("\n", [
            'CAPAUTH_NONCE_V1',
            "nonce={$nonce}",
            "client_nonce={$clientNonce}",
            "timestamp={$issuedAt}",
            "service={$service}",
            "expires={$expiresAt}",
        ]);
    }

    public function canonicalClaimsPayload(
        string $fingerprint,
        string $nonce,
        array  $claims,
    ): string {
        ksort($claims);
        $claimsJson = json_encode($claims, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        return implode("\n", [
            'CAPAUTH_CLAIMS_V1',
            "fingerprint={$fingerprint}",
            "nonce={$nonce}",
            "claims={$claimsJson}",
        ]);
    }

    // ── Fingerprint extraction ───────────────────────────────────────────────

    /**
     * Extract the 40-char uppercase fingerprint from an ASCII-armored public key.
     * Returns empty string on failure.
     */
    public function fingerprintFromArmor(string $armor): string {
        if (extension_loaded('gnupg')) {
            return $this->fingerprintViaExtension($armor);
        }
        return $this->fingerprintViaGpgBin($armor);
    }

    private function fingerprintViaExtension(string $armor): string {
        $gpg = new \gnupg();
        $gpg->seterrormode(\gnupg::ERROR_SILENT);
        $info = $gpg->import($armor);
        return strtoupper($info['fingerprint'] ?? '');
    }

    private function fingerprintViaGpgBin(string $armor): string {
        $gpgBin = $this->findGpgBin();
        if ($gpgBin === null) {
            return '';
        }
        $home = sys_get_temp_dir() . '/capauth_gpg_' . uniqid();
        @mkdir($home, 0700, true);
        try {
            $keyFile = $home . '/key.asc';
            file_put_contents($keyFile, $armor);
            $cmd    = [$gpgBin, '--homedir', $home, '--batch', '--with-colons', '--import-options', 'show-only', '--import', $keyFile];
            $output = $this->runProcess($cmd);
            foreach (explode("\n", $output) as $line) {
                $parts = explode(':', $line);
                if (isset($parts[0], $parts[9]) && in_array($parts[0], ['pub', 'fpr'], true)) {
                    $fp = strtoupper(trim($parts[9]));
                    if (strlen($fp) === 40) {
                        return $fp;
                    }
                }
            }
        } finally {
            $this->rmrfTmp($home);
        }
        return '';
    }

    // ── Signature verification ───────────────────────────────────────────────

    /**
     * Verify that $sigArmor is a valid detached/clear-text PGP signature over
     * $data made by the key in $publicKeyArmor.
     */
    public function verifySignature(string $data, string $sigArmor, string $publicKeyArmor): bool {
        if (trim($sigArmor) === '' || trim($publicKeyArmor) === '') {
            return false;
        }
        if (extension_loaded('gnupg')) {
            return $this->verifyViaExtension($data, $sigArmor, $publicKeyArmor);
        }
        return $this->verifyViaGpgBin($data, $sigArmor, $publicKeyArmor);
    }

    private function verifyViaExtension(string $data, string $sigArmor, string $publicKeyArmor): bool {
        $home = sys_get_temp_dir() . '/capauth_gnupg_' . uniqid();
        @mkdir($home, 0700, true);
        try {
            $gpg = new \gnupg();
            $gpg->seterrormode(\gnupg::ERROR_SILENT);
            $gpg->import($publicKeyArmor);

            // If sigArmor is a clear-signed message, verify the whole thing.
            if (str_contains($sigArmor, '-----BEGIN PGP SIGNED MESSAGE-----')) {
                $result = $gpg->verify($sigArmor, false, $data);
            } else {
                $result = $gpg->verify($data, $sigArmor);
            }
            return is_array($result) && count($result) > 0 && ($result[0]['summary'] & 0x01) === 0;
        } finally {
            $this->rmrfTmp($home);
        }
    }

    private function verifyViaGpgBin(string $data, string $sigArmor, string $publicKeyArmor): bool {
        $gpgBin = $this->findGpgBin();
        if ($gpgBin === null) {
            $this->logger->warning('CapAuth: gpg binary not found; signature verification skipped.');
            return false;
        }
        $home = sys_get_temp_dir() . '/capauth_gpg_' . uniqid();
        @mkdir($home, 0700, true);
        try {
            $keyFile  = $home . '/key.asc';
            $dataFile = $home . '/data.txt';
            $sigFile  = $home . '/sig.asc';
            file_put_contents($keyFile, $publicKeyArmor);
            file_put_contents($dataFile, $data);

            // Import key.
            $this->runProcess([$gpgBin, '--homedir', $home, '--batch', '--import', $keyFile]);

            // For clear-signed messages, verify the armored blob directly.
            if (str_contains($sigArmor, '-----BEGIN PGP SIGNED MESSAGE-----')) {
                file_put_contents($sigFile, $sigArmor);
                $output = $this->runProcess(
                    [$gpgBin, '--homedir', $home, '--batch', '--verify', $sigFile],
                    $exitCode,
                );
            } else {
                file_put_contents($sigFile, $sigArmor);
                $output = $this->runProcess(
                    [$gpgBin, '--homedir', $home, '--batch', '--verify', $sigFile, $dataFile],
                    $exitCode,
                );
            }
            return $exitCode === 0;
        } catch (\Throwable $e) {
            $this->logger->error('CapAuth signature verification error: ' . $e->getMessage());
            return false;
        } finally {
            $this->rmrfTmp($home);
        }
    }

    // ── Full auth response verification ─────────────────────────────────────

    /**
     * Verify a complete CapAuth authentication response.
     *
     * @return array{0:bool, 1:string}  [success, error_code]
     */
    public function verifyAuthResponse(
        string $fingerprint,
        string $nonceId,
        string $nonceSigArmor,
        array  $claims,
        string $claimsSigArmor,
        string $publicKeyArmor,
        array  $challengeCtx,
    ): array {
        if (trim($nonceSigArmor) === '') {
            return [false, 'invalid_nonce_signature'];
        }

        $noncePayload = $this->canonicalNoncePayload(
            $challengeCtx['nonce'],
            $challengeCtx['client_nonce_echo'],
            $challengeCtx['issued_at'],
            $challengeCtx['service'],
            $challengeCtx['expires_at'],
        );

        if (!$this->verifySignature($noncePayload, $nonceSigArmor, $publicKeyArmor)) {
            return [false, 'invalid_nonce_signature'];
        }

        // If claims are present they must also be signed.
        if (!empty($claims)) {
            if (trim($claimsSigArmor) === '') {
                return [false, 'invalid_claims_signature'];
            }
            $claimsPayload = $this->canonicalClaimsPayload($fingerprint, $nonceId, $claims);
            if (!$this->verifySignature($claimsPayload, $claimsSigArmor, $publicKeyArmor)) {
                return [false, 'invalid_claims_signature'];
            }
        }

        return [true, ''];
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /** Extract the PGP signature block from a clear-signed message. */
    private function extractSigFromSignedMessage(string $msg): ?string {
        if (!preg_match(
            '/-----BEGIN PGP SIGNATURE-----.+?-----END PGP SIGNATURE-----/s',
            $msg,
            $m,
        )) {
            return null;
        }
        return $m[0];
    }

    private function findGpgBin(): ?string {
        foreach (['gpg2', 'gpg'] as $bin) {
            $path = trim((string) shell_exec("command -v {$bin} 2>/dev/null"));
            if ($path !== '') {
                return $path;
            }
        }
        return null;
    }

    private function runProcess(array $cmd, int &$exitCode = 0): string {
        $proc = proc_open(
            $cmd,
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
        );
        if (!is_resource($proc)) {
            $exitCode = 1;
            return '';
        }
        $stdout   = stream_get_contents($pipes[1]);
        $stderr   = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($proc);
        return (string) $stdout;
    }

    private function rmrfTmp(string $dir): void {
        if (!is_dir($dir)) {
            return;
        }
        foreach (new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST,
        ) as $item) {
            $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
        }
        rmdir($dir);
    }
}
