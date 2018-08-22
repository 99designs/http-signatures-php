HTTP Signatures
===

PHP implementation of [HTTP Signatures][draft03] draft specification;
allowing cryptographic signing and verifying of [PSR7 messages][psr7].

See also:

* https://github.com/99designs/http-signatures-guzzlehttp
* https://github.com/99designs/http-signatures-ruby


Usage
---

Add [99designs/http-signatures][package] to your [composer.json][composer].

Configure a context with your algorithm, keys, headers to sign.
This is best placed in an application startup file.

```php
use HttpSignatures\Context;

$context = new Context([
  'keys' => ['examplekey' => 'secret-key-here'],
  'algorithm' => 'hmac-sha256',
  'headers' => ['(request-target)', 'Date', 'Accept'],
]);
```

If there's only one key in the `keys` hash, that will be used for signing.
Otherwise, specify one via `'signingKeyId' => 'examplekey'`.

### Messages

A message is assumed to be a PSR-7 compatible request or response object.

#### Signing a message

```php
$context->signer()->sign($message);
```

Now `$message` contains the signature headers:

```php
$message->headers->get('Signature');
// keyId="examplekey",algorithm="hmac-sha256",headers="...",signature="..."

$message->headers->get('Authorization');
// Signature keyId="examplekey",algorithm="hmac-sha256",headers="...",signature="..."
```

#### Adding a Digest header while signing

Include a ```Digest``` header automatically when signing:

```php
$context->signer()->signWithDigest($message);
$message->headers->get('digest');
// SHA-256=<base64SHA256Digest>
```

#### Verifying a signed message

```php
$context->verifier()->isValid($message); // true or false
```

#### Verifying a message digest

To confirm the body has a valid digest header and the header is a valid digest
of the message body:

```php
$context->verifier()->isValidDigest($message); // true or false
```

An all-in-one validation that the signature includes the digest, and the digest
is valid for the message body:


```php
$context->verifier()->isValidWithDigest($message); // true or false
```

### Symfony compatibility

Symfony requests normalize query strings which means the resulting request target can be incorrect. See https://github.com/symfony/psr-http-message-bridge/pull/30

When creating PSR-7 requests you use `withRequestTarget` to ensure the request target is correct. For example

```php
use Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory;
use Symfony\Component\HttpFoundation\Request;

$symfonyRequest = Request::create('/foo?b=1&a=2');
$psrRequest = (new DiactorosFactory())
	->createRequest($symfonyRequest)
	->withRequestTarget($symfonyRequest->getRequestUri());
```

## Contributing

Pull Requests are welcome.

[draft03]: http://tools.ietf.org/html/draft-cavage-http-signatures-03
[Symfony\Component\HttpFoundation\Request]: https://github.com/symfony/HttpFoundation/blob/master/Request.php
[composer]: https://getcomposer.org/
[package]: https://packagist.org/packages/99designs/http-signatures
[psr7]: http://www.php-fig.org/psr/psr-7/

## License

HTTP Signatures is licensed under [The MIT License (MIT)](LICENSE).
