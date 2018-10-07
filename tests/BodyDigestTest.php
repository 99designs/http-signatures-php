<?php

namespace HttpSignatures\tests;

use GuzzleHttp\Psr7\Request;
use HttpSignatures\BodyDigest;
use HttpSignatures\Context;

class BodyDigestTest extends \PHPUnit_Framework_TestCase
{
    private $context;

    public function setUp()
    {
        $this->bodyDigest = new BodyDigest();
    }

    public function testDigestSpecs()
    {
        $this->assertTrue($this->bodyDigest->isValidDigestSpec('sha256'));
        $this->assertTrue($this->bodyDigest->isValidDigestSpec('SHA'));
        $this->assertTrue($this->bodyDigest->isValidDigestSpec('SHA-512'));
        $this->assertTrue($this->bodyDigest->isValidDigestSpec('sha1'));
        $this->assertFalse($this->bodyDigest->isValidDigestSpec('md5'));
        $this->assertFalse($this->bodyDigest->isValidDigestSpec('sha384'));
    }

    public function testBodyDigestGeneration()
    {
        $digestContext = new Context([
            'keys' => ['secret1' => 'secret'],
            'algorithm' => 'hmac-sha256',
            'headers' => ['(request-target)', 'date'],
        ]);
        $messageNoBody = new Request('PUT', '/path?query=123');
        $messageWithBody = new Request('PUT', '/path?query=123', [], 'Some body message');
        $messageNoBody = $this->bodyDigest->setDigestHeader($messageNoBody);
        $messageWithBody = $this->bodyDigest->setDigestHeader($messageWithBody);
        $this->assertEquals(
            sizeof($messageNoBody->getHeader('Digest')),
            1
        );
        $this->assertEquals(
            'SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=',
            $messageNoBody->getHeader('Digest')[0]
        );
        $this->assertEquals(
            'SHA-256=rzVGO6XxaadG840dyi4fn8O6sCeSw/r1mZalGbPyjXM=',
            $messageWithBody->getHeader('Digest')[0]
        );
    }
}
