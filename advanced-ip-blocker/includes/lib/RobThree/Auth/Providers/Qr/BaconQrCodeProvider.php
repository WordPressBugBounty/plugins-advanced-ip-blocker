<?php

declare(strict_types=1);

namespace RobThree\Auth\Providers\Qr;

use BaconQrCode\Writer;
use SensitiveParameter;

class BaconQrCodeProvider implements IQRCodeProvider
{
    public function __construct(private readonly Writer $writer)
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getQRCodeImage(#[SensitiveParameter] string $qrtext, int $size): string
    {
        // Suppress warnings that may be thrown by the writer
        return @$this->writer->writeString($qrtext);
    }

    /**
     * {@inheritdoc}
     */
    public function getMimeType(): string
    {
        return 'image/svg+xml';
    }
}