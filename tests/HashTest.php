<?php

use PHPUnit\Framework\TestCase;
use Yohns\Security\Finding\Hash;
use Yohns\Core\Config;

class HashTest extends TestCase
{
	private Hash $hash;

	protected function setUp(): void
	{
		new Config(__DIR__.'/../Config');
		Config::set('salt', 'DJ)CmCzIV{B!kEIKbY\BzQsJC]d!c[?6ZXJ/?9B"@yKe-/G!+t5*Q-PRw](JXWt-');
		parent::setUp();
		$this->hash = new Hash();
		if (session_status() !== PHP_SESSION_ACTIVE) {
			session_start();
		}
	}

	public function testSaltCanBeSetAndRetrieved(): void
	{
		$salt = 'TestSalt123';
		$this->hash->setSalt($salt);
		$this->assertSame($salt, $this->hash->getSalt());
	}

	public function testSessionKeyCanBeSetAndRetrieved(): void
	{
		$key = 'CustomSessionKey';
		$this->hash->setSessionKey($key);
		$this->assertSame($key, $this->hash->getSessionKey());
	}

	public function testGenerateTokenCreatesValidToken(): void
	{
		$formId = 'testForm';
		$token = $this->hash->generateToken($formId);
		$this->assertNotEmpty($token);

		// Check session data
		$this->assertArrayHasKey($formId, $_SESSION[$this->hash->getSessionKey()]);
	}

	public function testValidateTokenReturnsTrueForValidToken(): void
	{
		$formId = 'testForm';
		$token = $this->hash->generateToken($formId);

		$isValid = $this->hash->validateToken($formId, $token);
		$this->assertTrue($isValid);

		// Ensure token cannot be reused
		$isValidAgain = $this->hash->validateToken($formId, $token);
		$this->assertFalse($isValidAgain);
	}

	public function testValidateTokenReturnsFalseForInvalidToken(): void
	{
		$formId = 'testForm';
		$this->hash->generateToken($formId);

		$isValid = $this->hash->validateToken($formId, 'InvalidToken');
		$this->assertFalse($isValid);
	}

	public function testGarbageCollectRemovesExpiredTokens(): void
	{
		$formId = 'testForm';
		$_SESSION[$this->hash->getSessionKey()][$formId][time() - (60 * 60 * 2)] = [
			'token' => 'expiredToken',
			'bytes' => 'expiredBytes'
		];

		$this->hash->generateToken($formId);
		$this->assertCount(1, $_SESSION[$this->hash->getSessionKey()][$formId]); // Only valid token remains
	}
}
