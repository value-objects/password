<?php

declare(strict_types = 1);

/**
 * All rights reserved.
 * @copyright Copyright (c) 2017 Gab Amba
 * @license https://github.com/gabbydgab/LicenseAgreement MIT License
 */

namespace ValueObjectTest\Password;

use PHPUnit\Framework\TestCase;
use ValueObject\Password\Password;

final class PasswordTest extends TestCase
{
    public function testEncryption()
    {
        $phrase = 'my_secure_password';
        $password = Password::encode($phrase);

        // assumed that this hash is stored somewhere
        $hash = password_hash($phrase, PASSWORD_BCRYPT, ['cost' => 12]);
        $this->assertTrue($password->isValid($hash));
    }

    public function testRehashing()
    {
        $phrase = 'my_secure_password';

        //  stored password with lesser cost
        $hash = password_hash($phrase, PASSWORD_BCRYPT, ['cost' => 10]);

        // updated script with new cost value
        $password = Password::encode($phrase);

        // validates that the password is backwards compatible
        $this->assertTrue($password->isValid($hash));

        // checks password if needs to be re-hash based on the current cost
        $this->assertTrue($password->needsRehash($hash));

        // create new hash
        $password->rehash();
        $this->assertNotEquals($hash, $password->getValue());

        // once persisted, then verifying the new
        $this->assertTrue($password->isValid($hash));
    }

    public function testNotEqualObjects()
    {
        $phrase = 'my_secure_password';
        $password = Password::encode($phrase);
        $password2 = Password::encode($phrase);

        $this->assertNotEquals($password->getValue(), $password2->getValue());
    }
}
