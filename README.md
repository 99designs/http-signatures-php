# HTTP Signatures


PHP implementation of [HTTP Signatures][draft03] draft specification;
allowing cryptographic signing and verifying of [PSR7 messages][psr7].

See also:

* https://github.com/99designs/http-signatures-guzzlehttp
* https://github.com/99designs/http-signatures-ruby


## Usage

1. Add [99designs/http-signatures][package] to your [composer.json][composer].
* A message is assumed to be a PSR-7 compatible Request or Response objects.
* A Context object is used to configure the signature parameters, and prepare
  the verifier functionality.

### Signing a message

Create a Context with your chosen algorithm, keys, and list of headers to sign.
  (This is best placed in an application startup file)

**Note**: If there's only one key in the `keys` hash, that will be used for signing.
Otherwise, specify one via `'signingKeyId' => 'examplekey'`.

#### HMAC (shared Secret) Signature type

```php
  use HttpSignatures\Context;
  
  $context = new Context([
    'keys' => ['key12' => 'secret-here'],
    'algorithm' => 'hmac-sha256',
    'headers' => ['(request-target)', 'Date', 'Accept'],
  ]);
```

#### RSA (Private Key) Signature type

Note: This library does not handle encrypted private keys, so this should
be presented un-encrypted to the key store.

```php
  use HttpSignatures\Context;
  
  $context = new Context([
    'keys' => ['key43' => file_get_contents('/path/to/privatekeyfile')],
    'algorithm' => 'rsa-sha256',
    'headers' => ['(request-target)', 'Date', 'Accept'],
  ]);
```
#### Signing the Message:

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

Many sites require a ``Digest`` header to be included in the signature. Add
a SHA256 digest to the headers using the ``signWithdigest`` method:

```php
  $context->signer()->signWithDigest($message);
```

### Verifying a Signed Message

Most parameters are derived from the Signature in the signed message, so the
Context can be created with fewer parameters.

It is probably most useful to create a Context with multilpe keys/certificates.
the signature verifier will look up the key using the keyId attribute of the
Signature header and use that to validate the signature. 

#### Verifying a HMAC signed message

A message signed with an hmac signature is verified using the same key as
the one used to sign the original message:

```php
  use HttpSignatures\Context;
  
  $context = new Context([
    'keys' => ['key300' => 'some-other-secret',
                'key12' => 'secret-here']
  ]);
  
  $context->verifier()->isValid($message); // true or false
```

#### Verifying a RSA signed message

An RSA signature is verified using the certificate associated with the
Private Key that created the message. Create a context by importing
the X.509 PEM format certificates in place of the 'secret':

```php
  use HttpSignatures\Context;
  
  $context = new Context([
    'keys' => ['key43' => file_get_contents('/path/to/certificate'),
               'key87' => $someOtherCertificate],
  $context->verifier()->isValid($message); // true or false
  ]);
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
