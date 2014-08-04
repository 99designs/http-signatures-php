# HTTP Signatures

PHP implementation of [HTTP Signatures][draft03] draft specification;
cryptographically sign and verify HTTP requests and responses.

See also:

* https://github.com/99designs/http-signatures-ruby


## Usage

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

A message is an HTTP request or response. A subset of the interface of
[Symfony\Component\HttpFoundation\Request] is expected; the ability to read
headers via `$message->headers->get($name)` and set them via
`$message->headers->set($name, $value)`, and for signing requests, methods to
read the path, query string and request method.

```php
use Symfony\Component\HttpFoundation\Request;

$message = Request::create('/path?query=123', 'GET');
$message->headers->replace(array(
  'Date' => 'Wed, 30 Jul 2014 16:40:19 -0700',
  'Accept' => 'llamas',
));
```

### Signing a message

```php
$context->signer()->sign($message);
```

Now `$message` contains the signature headers:

```php
$message->headers->get('Signature');
# keyId="examplekey",algorithm="hmac-sha256",headers="...",signature="..."

$message->headers->get('Authorization');
# Signature keyId="examplekey",algorithm="hmac-sha256",headers="...",signature="..."
```

### Verifying a signed message

```php
$context->verifier()->isValid($message); // true or false
```


## Contributing

Pull Requests are welcome.


[draft03]: http://tools.ietf.org/html/draft-cavage-http-signatures-03
[Symfony\Component\HttpFoundation\Request]: https://github.com/symfony/HttpFoundation/blob/master/Request.php
[composer]: https://getcomposer.org/
[package]: https://packagist.org/packages/99designs/http-signatures
