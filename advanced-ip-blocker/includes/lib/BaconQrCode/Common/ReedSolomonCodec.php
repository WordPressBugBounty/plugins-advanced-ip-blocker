<?php

declare(strict_types=1);

namespace BaconQrCode\Common;

use BaconQrCode\Exception\InvalidArgumentException;
use BaconQrCode\Exception\RuntimeException;
use SplFixedArray;

/**
 * Reed-Solomon codec for 8-bit characters.
 *
 * Based on libfec by Phil Karn, KA9Q.
 */
final class ReedSolomonCodec
{
    /**
     * Symbol size in bits.
     */
    private int $symbolSize;

    /**
     * Block size in symbols.
     */
    private int $blockSize;

    /**
     * First root of RS code generator polynomial, index form.
     */
    private int $firstRoot;

    /**
     * Primitive element to generate polynomial roots, index form.
     */
    private int $primitive;

    /**
     * Prim-th root of 1, index form.
     */
    private int $iPrimitive;

    /**
     * RS code generator polynomial degree (number of roots).
     */
    private int $numRoots;

    /**
     * Padding bytes at front of shortened block.
     */
    private int $padding;

    /**
     * Log lookup table.
     *
     * @var SplFixedArray
     */
    private SplFixedArray $alphaTo;

    /**
     * Anti-Log lookup table.
     *
     * @var SplFixedArray
     */
    private SplFixedArray $indexOf;

    /**
     * Generator polynomial.
     *
     * @var SplFixedArray
     */
    private SplFixedArray $generatorPoly;

    /**
     * @throws InvalidArgumentException if symbol size ist not between 0 and 8
     * @throws InvalidArgumentException if first root is invalid
     * @throws InvalidArgumentException if num roots is invalid
     * @throws InvalidArgumentException if padding is invalid
     * @throws RuntimeException if field generator polynomial is not primitive
     */
    public function __construct(
        int $symbolSize,
        int $gfPoly,
        int $firstRoot,
        int $primitive,
        int $numRoots,
        int $padding
    ) {
        if ($symbolSize < 0 || $symbolSize > 8) {
            throw new InvalidArgumentException('Symbol size must be between 0 and 8');
        }

        if ($firstRoot < 0 || $firstRoot >= (1 << $symbolSize)) {
            throw new InvalidArgumentException('First root must be between 0 and ' . (1 << $symbolSize));
        }

        if ($numRoots < 0 || $numRoots >= (1 << $symbolSize)) {
            throw new InvalidArgumentException('Num roots must be between 0 and ' . (1 << $symbolSize));
        }

        if ($padding < 0 || $padding >= ((1 << $symbolSize) - 1 - $numRoots)) {
            throw new InvalidArgumentException(
                'Padding must be between 0 and ' . ((1 << $symbolSize) - 1 - $numRoots)
            );
        }

        $this->symbolSize = $symbolSize;
        $this->blockSize = (1 << $symbolSize) - 1;
        $this->padding = $padding;
        $this->alphaTo = SplFixedArray::fromArray(array_fill(0, $this->blockSize + 1, 0), false);
        $this->indexOf = SplFixedArray::fromArray(array_fill(0, $this->blockSize + 1, 0), false);

        $this->indexOf[0] = $this->blockSize;
        $this->alphaTo[$this->blockSize] = 0;

        $sr = 1;

        for ($i = 0; $i < $this->blockSize; ++$i) {
            $this->indexOf[$sr] = $i;
            $this->alphaTo[$i]  = $sr;

            $sr <<= 1;

            if ($sr & (1 << $symbolSize)) {
                $sr ^= $gfPoly;
            }

            $sr &= $this->blockSize;
        }

        if (1 !== $sr) {
            throw new RuntimeException('Field generator polynomial is not primitive');
        }

        $this->generatorPoly = SplFixedArray::fromArray(array_fill(0, $numRoots + 1, 0), false);
        $this->firstRoot = $firstRoot;
        $this->primitive = $primitive;
        $this->numRoots = $numRoots;

        for ($iPrimitive = 1; ($iPrimitive % $primitive) !== 0; $iPrimitive += $this->blockSize) {
        }

        $this->iPrimitive = intdiv($iPrimitive, $primitive);

        $this->generatorPoly[0] = 1;

        for ($i = 0, $root = $firstRoot * $primitive; $i < $numRoots; ++$i, $root += $primitive) {
            $this->generatorPoly[$i + 1] = 1;

            for ($j = $i; $j > 0; $j--) {
                if ($this->generatorPoly[$j] !== 0) {
                    $this->generatorPoly[$j] = $this->generatorPoly[$j - 1] ^ $this->alphaTo[
                        $this->modNn($this->indexOf[$this->generatorPoly[$j]] + $root)
                    ];
                } else {
                    $this->generatorPoly[$j] = $this->generatorPoly[$j - 1];
                }
            }

            $this->generatorPoly[$j] = $this->alphaTo[$this->modNn($this->indexOf[$this->generatorPoly[0]] + $root)];
        }

        for ($i = 0; $i <= $numRoots; ++$i) {
            $this->generatorPoly[$i] = $this->indexOf[$this->generatorPoly[$i]];
        }
    }

    /**
     * Encodes data and writes result back into parity array.
     */
    public function encode(SplFixedArray $data, SplFixedArray $parity): void
    {
        for ($i = 0; $i < $this->numRoots; ++$i) {
            $parity[$i] = 0;
        }

        $iterations = $this->blockSize - $this->numRoots - $this->padding;

        for ($i = 0; $i < $iterations; ++$i) {
            $feedback = $this->indexOf[$data[$i] ^ $parity[0]];

            if ($feedback !== $this->blockSize) {
                $feedback = $this->modNn($this->blockSize - $this->generatorPoly[$this->numRoots] + $feedback);

                for ($j = 1; $j < $this->numRoots; ++$j) {
                    $parity[$j] = $parity[$j] ^ $this->alphaTo[
                        $this->modNn($feedback + $this->generatorPoly[$this->numRoots - $j])
                    ];
                }
            }

            for ($j = 0; $j < $this->numRoots - 1; ++$j) {
                $parity[$j] = $parity[$j + 1];
            }

            if ($feedback !== $this->blockSize) {
                $parity[$this->numRoots - 1] = $this->alphaTo[$this->modNn($feedback + $this->generatorPoly[0])];
            } else {
                $parity[$this->numRoots - 1] = 0;
            }
        }
    }

    /**
     * Decodes received data.
     */
    public function decode(SplFixedArray $data, ?SplFixedArray $erasures = null): ?int
    {
        $numRootsPlusOne = SplFixedArray::fromArray(array_fill(0, $this->numRoots + 1, 0), false);
        $numRoots = SplFixedArray::fromArray(array_fill(0, $this->numRoots, 0), false);

        $lambda = clone $numRootsPlusOne;
        $b = clone $numRootsPlusOne;
        $t = clone $numRootsPlusOne;
        $omega = clone $numRootsPlusOne;
        $root = clone $numRoots;
        $loc = clone $numRoots;

        $numErasures = (null !== $erasures ? count($erasures) : 0);

        $syndromes = SplFixedArray::fromArray(array_fill(0, $this->numRoots, $data[0]), false);

        for ($i = 1; $i < $this->blockSize - $this->padding; ++$i) {
            for ($j = 0; $j < $this->numRoots; ++$j) {
                if ($syndromes[$j] === 0) {
                    $syndromes[$j] = $data[$i];
                } else {
                    $syndromes[$j] = $data[$i] ^ $this->alphaTo[
                        $this->modNn($this->indexOf[$syndromes[$j]] + ($this->firstRoot + $j) * $this->primitive)
                    ];
                }
            }
        }

        $syndromeError = 0;

        for ($i = 0; $i < $this->numRoots; ++$i) {
            $syndromeError |= $syndromes[$i];
            $syndromes[$i] = $this->indexOf[$syndromes[$i]];
        }

        if (! $syndromeError) {
            return 0;
        }

        $lambda[0] = 1;

        if ($numErasures > 0) {
            $lambda[1] = $this->alphaTo[$this->modNn($this->primitive * ($this->blockSize - 1 - $erasures[0]))];

            for ($i = 1; $i < $numErasures; ++$i) {
                $u = $this->modNn($this->primitive * ($this->blockSize - 1 - $erasures[$i]));

                for ($j = $i + 1; $j > 0; --$j) {
                    $tmp = $this->indexOf[$lambda[$j - 1]];

                    if ($tmp !== $this->blockSize) {
                        $lambda[$j] = $lambda[$j] ^ $this->alphaTo[$this->modNn($u + $tmp)];
                    }
                }
            }
        }

        for ($i = 0; $i <= $this->numRoots; ++$i) {
            $b[$i] = $this->indexOf[$lambda[$i]];
        }

        $r  = $numErasures;
        $el = $numErasures;

        while (++$r <= $this->numRoots) {
            $discrepancyR = 0;

            for ($i = 0; $i < $r; ++$i) {
                if ($lambda[$i] !== 0 && $syndromes[$r - $i - 1] !== $this->blockSize) {
                    $discrepancyR ^= $this->alphaTo[
                        $this->modNn($this->indexOf[$lambda[$i]] + $syndromes[$r - $i - 1])
                    ];
                }
            }

            $discrepancyR = $this->indexOf[$discrepancyR];

            if ($discrepancyR === $this->blockSize) {
                $tmp = $b->toArray();
                array_unshift($tmp, $this->blockSize);
                array_pop($tmp);
                $b = SplFixedArray::fromArray($tmp, false);
                continue;
            }

            $t[0] = $lambda[0];

            for ($i = 0; $i < $this->numRoots; ++$i) {
                if ($b[$i] !== $this->blockSize) {
                    $t[$i + 1] = $lambda[$i + 1] ^ $this->alphaTo[$this->modNn($discrepancyR + $b[$i])];
                } else {
                    $t[$i + 1] = $lambda[$i + 1];
                }
            }

            if (2 * $el <= $r + $numErasures - 1) {
                $el = $r + $numErasures - $el;

                for ($i = 0; $i <= $this->numRoots; ++$i) {
                    $b[$i] = (
                        $lambda[$i] === 0
                        ? $this->blockSize
                        : $this->modNn($this->indexOf[$lambda[$i]] - $discrepancyR + $this->blockSize)
                    );
                }
            } else {
                $tmp = $b->toArray();
                array_unshift($tmp, $this->blockSize);
                array_pop($tmp);
                $b = SplFixedArray::fromArray($tmp, false);
            }

            $lambda = clone $t;
        }

        $degLambda = 0;

        for ($i = 0; $i <= $this->numRoots; ++$i) {
            $lambda[$i] = $this->indexOf[$lambda[$i]];

            if ($lambda[$i] !== $this->blockSize) {
                $degLambda = $i;
            }
        }

        $reg = clone $lambda;
        $reg[0] = 0;
        $count = 0;
        $i = 1;

        for ($k = $this->iPrimitive - 1; $i <= $this->blockSize; ++$i, $k = $this->modNn($k + $this->iPrimitive)) {
            $q = 1;

            for ($j = $degLambda; $j > 0; $j--) {
                if ($reg[$j] !== $this->blockSize) {
                    $reg[$j] = $this->modNn($reg[$j] + $j);
                    $q ^= $this->alphaTo[$reg[$j]];
                }
            }

            if ($q !== 0) {
                continue;
            }

            $root[$count] = $i;
            $loc[$count] = $k;

            if (++$count === $degLambda) {
                break;
            }
        }

        if ($degLambda !== $count) {
            return null;
        }

        $degOmega = $degLambda - 1;

        for ($i = 0; $i <= $degOmega; ++$i) {
            $tmp = 0;

            for ($j = $i; $j >= 0; --$j) {
                if ($syndromes[$i - $j] !== $this->blockSize && $lambda[$j] !== $this->blockSize) {
                    $tmp ^= $this->alphaTo[$this->modNn($syndromes[$i - $j] + $lambda[$j])];
                }
            }

            $omega[$i] = $this->indexOf[$tmp];
        }

        for ($j = $count - 1; $j >= 0; --$j) {
            $num1 = 0;

            for ($i = $degOmega; $i >= 0; $i--) {
                if ($omega[$i] !== $this->blockSize) {
                    $num1 ^= $this->alphaTo[$this->modNn($omega[$i] + $i * $root[$j])];
                }
            }

            $num2 = $this->alphaTo[$this->modNn($root[$j] * ($this->firstRoot - 1) + $this->blockSize)];
            $den  = 0;

            for ($i = min($degLambda, $this->numRoots - 1) & ~1; $i >= 0; $i -= 2) {
                if ($lambda[$i + 1] !== $this->blockSize) {
                    $den ^= $this->alphaTo[$this->modNn($lambda[$i + 1] + $i * $root[$j])];
                }
            }

            if ($num1 !== 0 && $loc[$j] >= $this->padding) {
                $data[$loc[$j] - $this->padding] = $data[$loc[$j] - $this->padding] ^ (
                    $this->alphaTo[
                        $this->modNn(
                            $this->indexOf[$num1] + $this->indexOf[$num2] + $this->blockSize - $this->indexOf[$den]
                        )
                    ]
                );
            }
        }

        if (null !== $erasures) {
            if (count($erasures) < $count) {
                $erasures->setSize($count);
            }

            for ($i = 0; $i < $count; $i++) {
                $erasures[$i] = $loc[$i];
            }
        }

        return $count;
    }

    /**
     * Computes $x % GF_SIZE, where GF_SIZE is 2**GF_BITS - 1, without a slow divide.
     */
    private function modNn(int $x): int
    {
        while ($x >= $this->blockSize) {
            $x -= $this->blockSize;
            $x = ($x >> $this->symbolSize) + ($x & $this->blockSize);
        }

        return $x;
    }
}
