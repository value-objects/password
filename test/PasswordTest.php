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

        $this->assertTrue($password->isValid("{$password}"));
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
        $newHash = $password->rehash();
        $this->assertNotEquals("{$password}", "{$newHash}");

        // once persisted, then verifying the new
        $this->assertTrue($password->isValid($hash));
    }

    public function testNotEqualObjects()
    {
        $phrase = 'my_secure_password';
        $password = Password::encode($phrase);
        $password2 = Password::encode($phrase);

        $this->assertNotEquals("{$password}", "{$password2}");
    }

    public function testInvalidHasShouldReturnFalse()
    {
        $phrase = 'my_secure_password';
        $password = Password::encode($phrase);

        // assumed that this hash is stored somewhere
        $othersPassword = Password::encode('others_password');
        $this->assertFalse($password->isValid("{$othersPassword}"));
    }

    public function testRehashingDifferentPhraseIsNotAllowed()
    {
        $phrase = 'my_secure_password';
        $password = Password::encode($phrase);

        // assumed that this hash is stored somewhere
        $othersPassword = Password::encode('others_password');
        $this->assertFalse($password->needsRehash("{$othersPassword}"));
    }

    public function testChangingOfPassword()
    {
        $password = Password::encode('my_secure_password');

        // changing the password
        $newPassword = $password->changeTo("new_secure_password");

        // upon update, the old hash should be invalid
        $this->assertFalse($newPassword->isValid("{$password}"));

        // new valid hash
        $this->assertTrue($newPassword->isValid("{$newPassword}"));
    }
}
