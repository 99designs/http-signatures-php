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

$context = new Context(array(
  'keys' => array('examplekey' => 'secret-key-here'),
  'algorithm' => 'hmac-sha256',
  'headers' => array('(request-target)', 'Date', 'Accept'),
));
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

#### Verifying a signed message

```php
$context->verifier()->isValid($message); // true or false
```

### Symfony Integration

Also included is a `HttpMessageFactory` class for converting Symfony `Request` objects into PSR-7 compatible messages.

```php
$symfonyRequest = \Symfony\Component\HttpFoundation\Request::create('/foo');
$psr7Factory = new \HttpSignatures\HttpMessageFactory();
$psrRequest = $psr7Factory->createRequest($symfonyRequest);
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
