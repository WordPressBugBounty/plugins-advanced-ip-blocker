<?php

declare(strict_types=1);

namespace RobThree\Auth;

use RobThree\Auth\Providers\Qr\IQRCodeProvider;
use RobThree\Auth\Providers\Rng\CSRNGProvider;
use RobThree\Auth\Providers\Rng\IRNGProvider;
use RobThree\Auth\Providers\Time\HttpTimeProvider;
use RobThree\Auth\Providers\Time\ITimeProvider;
use RobThree\Auth\Providers\Time\LocalMachineTimeProvider;
use RobThree\Auth\Providers\Time\NTPTimeProvider;
use SensitiveParameter;

use function hash_equals;

class TwoFactorAuth
{
    private static string $_base32dict = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=';

    /** @var array<string> */
    private static array $_base32;

    /** @var array<string, int> */
    private static array $_base32lookup = array();

    public function __construct(
        private IQRCodeProvider    $qrcodeprovider,
        private readonly ?string   $issuer = null,
        private readonly int       $digits = 6,
        private readonly int       $period = 30,
        private readonly Algorithm $algorithm = Algorithm::Sha1,
        private ?IRNGProvider      $rngprovider = null,
        private ?ITimeProvider     $timeprovider = null
    ) {
        if ($this->digits <= 0) {
            throw new TwoFactorAuthException('Digits must be > 0');
        }

        if ($this->period <= 0) {
            throw new TwoFactorAuthException('Period must be int > 0');
        }

        self::$_base32 = str_split(self::$_base32dict);
        self::$_base32lookup = array_flip(self::$_base32);
    }

    /**
     * Create a new secret
     */
    public function createSecret(int $bits = 160): string
    {
        $secret = '';
        $bytes = (int)ceil($bits / 5);
        $rngprovider = $this->getRngProvider();
        $rnd = $rngprovider->getRandomBytes($bytes);
        for ($i = 0; $i < $bytes; $i++) {
            $secret .= self::$_base32[ord($rnd[$i]) & 31];
        }

        return $secret;
    }

    /**
     * Calculate the code with given secret and point in time
     */
    public function getCode(#[SensitiveParameter] string $secret, ?int $time = null): string
    {
        $secretkey = $this->base32Decode($secret);

        $timestamp = "\0\0\0\0" . pack('N*', $this->getTimeSlice($this->getTime($time)));
        $hashhmac = hash_hmac($this->algorithm->value, $timestamp, $secretkey, true);
        $hashpart = substr($hashhmac, ord(substr($hashhmac, -1)) & 0x0F, 4);
        $value = unpack('N', $hashpart);
        $value = $value[1] & 0x7FFFFFFF;

        return str_pad((string)($value % 10 ** $this->digits), $this->digits, '0', STR_PAD_LEFT);
    }

    /**
     * Check if the code is correct. This will accept codes starting from ($discrepancy * $period) sec ago to ($discrepancy * period) sec from now
     */
    public function verifyCode(string $secret, string $code, int $discrepancy = 1, ?int $time = null, ?int &$timeslice = 0): bool
    {
        $timestamp = $this->getTime($time);

        $timeslice = 0;

        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            $ts = $timestamp + ($i * $this->period);
            $slice = $this->getTimeSlice($ts);
            $timeslice = hash_equals($this->getCode($secret, $ts), $code) ? $slice : $timeslice;
        }

        return $timeslice > 0;
    }

    /**
     * Get data-uri of QRCode
     */
    public function getQRCodeImageAsDataUri(string $label, #[SensitiveParameter] string $secret, int $size = 200): string
    {
        if ($size <= 0) {
            throw new TwoFactorAuthException('Size must be > 0');
        }

        return 'data:'
            . $this->qrcodeprovider->getMimeType()
            . ';base64,'
            . base64_encode($this->qrcodeprovider->getQRCodeImage($this->getQRText($label, $secret), $size));
    }

    /**
     * Compare default timeprovider with specified timeproviders and ensure the time is within the specified number of seconds (leniency)
     * @param array<ITimeProvider> $timeproviders
     * @throws TwoFactorAuthException
     */
    public function ensureCorrectTime(?array $timeproviders = null, int $leniency = 5): void
    {
        if ($timeproviders === null) {
            $timeproviders = array(
                new NTPTimeProvider(),
                new HttpTimeProvider(),
            );
        }

        $timeprovider = $this->getTimeProvider();

        foreach ($timeproviders as $t) {
            if (!($t instanceof ITimeProvider)) {
                throw new TwoFactorAuthException('Object does not implement ITimeProvider');
            }

            if (abs($timeprovider->getTime() - $t->getTime()) > $leniency) {
                throw new TwoFactorAuthException(sprintf('Time for timeprovider is off by more than %d seconds when compared to %s', $leniency, get_class($t)));
            }
        }
    }

    /**
     * Builds a string to be encoded in a QR code
     */
    public function getQRText(string $label, #[SensitiveParameter] string $secret): string
    {
        return 'otpauth://totp/' . rawurlencode($label)
            . '?secret=' . rawurlencode($secret)
            . '&issuer=' . rawurlencode((string)$this->issuer)
            . '&period=' . $this->period
            . '&algorithm=' . rawurlencode(strtoupper($this->algorithm->value))
            . '&digits=' . $this->digits;
    }

    /**
     * @throws TwoFactorAuthException
     */
    public function getRngProvider(): IRNGProvider
    {
        return $this->rngprovider ??= new CSRNGProvider();
    }

    public function getTimeProvider(): ITimeProvider
    {
        return $this->timeprovider ??= new LocalMachineTimeProvider();
    }

    private function getTime(?int $time = null): int
    {
        return $time ?? $this->getTimeProvider()->getTime();
    }

    private function getTimeSlice(?int $time = null, int $offset = 0): int
    {
        return (int)floor($time / $this->period) + ($offset * $this->period);
    }

    private function base32Decode(string $value): string
    {
        if ($value === '') {
            return '';
        }

        if (preg_match('/[^' . preg_quote(self::$_base32dict, '/') . ']/', $value) !== 0) {
            throw new TwoFactorAuthException('Invalid base32 string');
        }

        $buffer = '';
        foreach (str_split($value) as $char) {
            if ($char !== '=') {
                $buffer .= str_pad(decbin(self::$_base32lookup[$char]), 5, '0', STR_PAD_LEFT);
            }
        }
        $length = strlen($buffer);
        $blocks = trim(chunk_split(substr($buffer, 0, $length - ($length % 8)), 8, ' '));

        $output = '';
        foreach (explode(' ', $blocks) as $block) {
            $output .= chr(bindec(str_pad($block, 8, '0', STR_PAD_RIGHT)));
        }

        return $output;
    }
}
