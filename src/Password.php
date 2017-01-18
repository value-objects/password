<?php

declare(strict_types = 1);

/**
 * All rights reserved.
 * @copyright Copyright (c) 2017 Gab Amba
 * @license https://github.com/gabbydgab/LicenseAgreement MIT License
 */

namespace ValueObject\Password;

final class Password
{
    /**
     * User input string
     *
     * @var string
     */
    private $phrase;

    /**
     * Auto-generated string
     *
     * @var string
     */
    private $hash;

    /**
     *
     * @uses NAMED CONSTRUCTOR. See http://verraes.net/2014/06/named-constructors-in-php/
     * @param string $phrase
     * @return void
     */
    private function __construct(string $phrase)
    {
        $this->phrase = $phrase; // stored for rehashing
        $this->hash = password_hash($this->phrase, PASSWORD_BCRYPT, ['cost' => 12]);
    }

    /**
     * Since this uses __toString(), it will return the hash value as an object.
     *
     * @param string $phrase
     * @return Password
     */
    public static function encode(string $phrase) : Password
    {
        return new Password($phrase);
    }

    public function isValid(string $hash)
    {
        return \password_verify($this->phrase, $hash);
    }

    public function rehash()
    {
        return self::encode($this->phrase);
    }

    public function needsRehash(string $hash)
    {
        return \password_needs_rehash($hash, PASSWORD_BCRYPT, ['cost' => 12]);
    }

    /**
     * Returns the generated hash value
     *
     * This magic method is not allowed during testing.
     * @see https://github.com/sebastianbergmann/phpunit/issues/934
     * @return string
     */
    public function __toString() : string
    {
        return $this->hash;
    }

    /**
     * IMPORTANT: DO NOT USE THIS IN ACTUAL IMPLEMENTATION.
     * THIS IS FOR UNIT TESTING PURPOSES ONLY
     *
     * Returns the generated hash value (hack to run __toString method during test)
     *
     * @deprecated since version 0.1.0
     * @return string
     */
    public function getValue() : string
    {
        return self::__toString();
    }
}
