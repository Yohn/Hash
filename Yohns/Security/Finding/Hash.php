<?php

namespace Yohns\Security\Finding;

use Yohns\Core\Config;

/**
 * Class Hash
 *
 * Provides functionality for generating, validating, and managing secure tokens and salted data.
 */
class Hash
{
	/**
	 * @var string|null Salt used for hashing tokens.
	 */
	private ?string $salt = null;

	/**
	 * @var string Session key for token storage.
	 */
	private string $sessionKey = 'NemoTokens';

	/**
	 * Sets the salt value.
	 *
	 * @param string $salt The salt to be used for token generation.
	 * @return self
	 */
	public function setSalt(string $salt): self
	{
		$this->salt = $salt;
		return $this;
	}

	/**
	 * Gets the salt value, initializing it from configuration if not set.
	 *
	 * @return string
	 */
	public function getSalt(): string
	{
		if (empty($this->salt)) {
			$saltFromConfig = Config::get('salt');
			if (!$saltFromConfig) {
				$saltFromConfig = 'DJ)CmCzIV{B!kEIKbY\BzQsJC]d!c[?6ZXJ/?9B"@yKe-/G!+t5*Q-PRw](JXWt-';
			}
			$this->setsalt($saltFromConfig);
		}
		return $this->salt;
	}

	/**
	 * Sets the session key. Defaults to 'NemoTokens'
	 *
	 * @param string $key The session key to store tokens.
	 * @return self
	 */
	public function setSessionKey(string $key): self
	{
		$this->sessionKey = $key;
		return $this;
	}

	/**
	 * Retrieves the session key.
	 *
	 * @return string The session key.
	 */
	public function getSessionKey(): string
	{
		return $this->sessionKey;
	}

	/**
	 * Generates a CSRF token for a specific form and stores it in the session.
	 *
	 * @param string $formId The unique identifier for the form.
	 * @return string The generated CSRF token.
	 * @throws \Exception If unable to generate random bytes.
	 */
	public function generateToken(string $formId): string
	{
		if (session_status() !== PHP_SESSION_ACTIVE) {
			session_start();
		}

		$timestamp = time();
		$bytes = random_bytes(32);
		$compact = $this->compactToken($formId, $bytes);
		$this->garbageCollect();

		$_SESSION[$this->getSessionKey()][$formId][$timestamp] = [
			'bytes' => bin2hex($bytes),
			'token' => $compact['token']
		];

		$this->garbageCollect();

		return $compact['token'];
	}

	/**
	 * Validates a submitted CSRF token against the stored tokens.
	 *
	 * @param string $formId The unique identifier for the form.
	 * @param string $submittedToken The token submitted via the form.
	 * @return bool True if the token is valid, false otherwise.
	 */
	public function validateToken(string $formId, string $submittedToken): bool
	{
		if (session_status() !== PHP_SESSION_ACTIVE) {
			session_start();
		}

		$sessionData = $_SESSION[$this->getSessionKey()][$formId] ?? null;

		if (is_array($sessionData)) {
			foreach ($sessionData as $timestamp => $tokens) {
				if (hash_equals($tokens['token'], $submittedToken)) {
					// Token is valid; remove it to prevent reuse
					unset($_SESSION[$this->getSessionKey()][$formId][$timestamp]);
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Compacts form ID and bytes into a secure token using HMAC.
	 *
	 * @param string $formId The unique identifier for the form.
	 * @param string $bytes The random bytes generated for the token.
	 * @return array Contains 'token' and 'bytes' keys.
	 */
	private function compactToken(string $formId, string $bytes): array
	{
		$salt = $this->getSalt();
		$wbytes = bin2hex($bytes);
		$data = $salt . $formId . $wbytes;
		$token = hash_hmac('sha256', $data, $salt);

		return [
			'token' => $token,
			'bytes' => $wbytes
		];
	}

	/**
	 * Removes expired tokens from the session to prevent session bloat.
	 *
	 * Tokens older than one hour are considered expired.
	 *
	 * @return void
	 */
	private function garbageCollect(): void
	{
		$expiryTime = time() - (60 * 60); // Tokens older than 1 hour are expired

		if (!isset($_SESSION[$this->getSessionKey()])) {
			return;
		}

		foreach ($_SESSION[$this->getSessionKey()] as $formId => &$formTokens) {
			foreach ($formTokens as $timestamp => $tokens) {
				if ($timestamp < $expiryTime) {
					unset($formTokens[$timestamp]);
				}
			}

			// If no tokens remain for the form, remove the form entry
			if (empty($formTokens)) {
				unset($_SESSION[$this->getSessionKey()][$formId]);
			}
		}
	}
}
