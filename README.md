# Hash Library

A secure and efficient PHP library for generating, validating, and managing tokens.

---

## Installation

Install the package via Composer:

```bash
composer require yohns/hash
```

---

## Usage

### 1. Generating a Token

Use the `generateToken` method to create a secure token.

```php
use Yohns\Security\Finding\Hash;

$token = Hash::generateToken('form-id'); // This value will be used again to validate the token
// add token to form
echo '<input type="hidden" name="YohnsPatch" value="'.$token.'">';
```

---

### 2. Validating a Token

Verify the validity of a token with the `validateToken` method.

```php
use Yohns\Security\Finding\Hash;

$isValid = Hash::validateToken('form-id', $_POST['YohnsPatch']);
if ($isValid) {
	echo 'Token is valid!';
} else {
	echo 'Token is invalid or expired.';
}
```

---

### 3. Garbage Collection

Remove expired tokens to maintain optimal performance.

```php
use Yohns\Security\Finding\Hash;

Hash::garbageCollect();
echo 'Expired tokens removed.';
```

---

## Running Tests

Ensure everything works as expected by running the test suite:

```bash
composer test
```

---

## Requirements

- PHP 8.1 or later, 8.3 preferred
- Composer
- [Yohns\Core\Config](https://github.com/Yohn/Config)

---

## License

This library is licensed under [MIT License](LICENSE).

---

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
