<?php

namespace HttpSignatures\tests;

use GuzzleHttp\Psr7\Request;
use HttpSignatures\Context;
use HttpSignatures\Tests\TestKeys;

class ContextTest extends \PHPUnit_Framework_TestCase
{
    private $context;

    public function setUp()
    {
        $this->noDigestContext = new Context([
            'keys' => ['pda' => 'secret'],
            'algorithm' => 'hmac-sha256',
            'headers' => ['(request-target)', 'date'],
        ]);
        $this->withDigestContext = new Context([
            'keys' => ['pda' => 'secret'],
            'algorithm' => 'hmac-sha256',
            'headers' => ['(request-target)', 'date', 'digest'],
        ]);
        $this->sha1context = new Context([
            'keys' => ['rsa1' => TestKeys::rsaPrivateKey],
            'algorithm' => 'rsa-sha1',
            'headers' => ['(request-target)', 'date'],
        ]);
        $this->sha256context = new Context([
            'keys' => ['rsa1' => TestKeys::rsaPrivateKey],
            'algorithm' => 'rsa-sha256',
            'headers' => ['(request-target)', 'date'],
        ]);
    }

    public function testSignerNoDigestAction()
    {
        $message = new Request('GET', '/path?query=123', ['date' => 'today', 'accept' => 'llamas']);
        $message = $this->noDigestContext->signer()->sign($message);

        $expectedString = implode(',', [
            'keyId="pda"',
            'algorithm="hmac-sha256"',
            'headers="(request-target) date"',
            'signature="SFlytCGpsqb/9qYaKCQklGDvwgmrwfIERFnwt+yqPJw="',
        ]);

        $this->assertEquals(
            $expectedString,
            $message->getHeader('Signature')[0]
        );

        $this->assertEquals(
            'Signature ' . $expectedString,
            $message->getHeader('Authorization')[0]
        );
    }

    public function testSignerAddDigestToHeadersList()
    {
        $message = new Request(
            'POST',
            '/path/to/things?query=123',
            ['date' => 'today', 'accept' => 'llamas'],
            'Thing to POST'
        );
        $message = $this->noDigestContext->signer()->signWithDigest($message);

        $expectedString = implode(',', [
            'keyId="pda"',
            'algorithm="hmac-sha256"',
            'headers="(request-target) date digest"',
            'signature="HH6R3OJmJbKUFqqL0tGVIIb7xi1WbbSh/HBXHUtLkUs="',
        ]);
        $expectedDigestHeader = 'SHA-256=rEcNhYZoBKiR29D30w1JcgArNlF8rXIXf5MnIL/4kcc=';

        $this->assertEquals(
            $expectedString,
            $message->getHeader('Signature')[0]
        );

        $this->assertEquals(
            $expectedDigestHeader,
            $message->getHeader('Digest')[0]
        );

        $this->assertEquals(
            'Signature ' . $expectedString,
            $message->getHeader('Authorization')[0]
        );
    }

    public function testSignerReplaceDigest()
    {
        $message = new Request(
            'PUT',
            '/things/thething?query=123',
            ['date' => 'today', 'accept' => 'llamas', 'Digest' => 'SHA-256=E/P+4y4x6EySO9qNAjCtQKxVwE1xKsNI/k+cjK+vtLU='],
            'Thing to PUT at /things/thething please...');
        $message = $this->noDigestContext->signer()->signWithDigest($message);

        $expectedString = implode(',', [
            'keyId="pda"',
            'algorithm="hmac-sha256"',
            'headers="(request-target) date digest"',
            'signature="Hyatt1lSR/4XLI9Gcx8XOEKiG8LVktH7Lfr+0tmhwRU="',
        ]);
        $expectedDigestHeader = 'SHA-256=mulOx+77mQU1EbPET50SCGA4P/4bYxVCJA1pTwJsaMw=';

        $this->assertEquals(
            $expectedString,
            $message->getHeader('Signature')[0]
        );

        $this->assertEquals(
            $expectedDigestHeader,
            $message->getHeader('Digest')[0]
        );

        $this->assertEquals(
            'Signature ' . $expectedString,
            $message->getHeader('Authorization')[0]
        );
    }

    public function testSignerNewDigestIsInHeaderList()
    {
        $message = new Request(
            'POST',
            '/path?query=123',
            ['date' => 'today', 'accept' => 'llamas'],
            'Stuff that belongs in /path'
        );
        $message = $this->withDigestContext->signer()->signWithDigest($message);

        $expectedString = implode(',', [
            'keyId="pda"',
            'algorithm="hmac-sha256"',
            'headers="(request-target) date digest"',
            'signature="p8gQHs59X2WzQLUecfmxm1YO0OBTCNKldRZZBQsepfk="',
        ]);
        $expectedDigestHeader = 'SHA-256=jnSMEfBSum4Rh2k6/IVFyvLuQLmGYwMAGBS9WybyDqQ=';

        $this->assertEquals(
            $expectedString,
            $message->getHeader('Signature')[0]
        );

        $this->assertEquals(
            $expectedDigestHeader,
            $message->getHeader('Digest')[0]
        );

        $this->assertEquals(
            'Signature ' . $expectedString,
            $message->getHeader('Authorization')[0]
        );
    }

    public function testSignerNewDigestWithoutBody()
    {
        $message = new Request(
            'GET', '/path?query=123',
            ['date' => 'today', 'accept' => 'llamas']
        );
        $message = $this->withDigestContext->signer()->signWithDigest($message);

        $expectedString = implode(',', [
            'keyId="pda"',
            'algorithm="hmac-sha256"',
            'headers="(request-target) date digest"',
            'signature="7iFqqryI6I9opV/Zp3eEg6PDY1tKw/3GqioOM7ACHHA="',
        ]);
        $zeroLengthStringDigest = 'SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=';

        $this->assertEquals(
            $expectedString,
            $message->getHeader('Signature')[0]
        );

        $this->assertEquals(
            $zeroLengthStringDigest,
            $message->getHeader('Digest')[0]
        );

        $this->assertEquals(
            'Signature ' . $expectedString,
            $message->getHeader('Authorization')[0]
        );
    }

    public function testVerifier()
    {
        $message = $this->noDigestContext->signer()->sign(
            new Request(
                'GET',
                '/path?query=123',
                [
                    'Signature' => 'keyId="pda",algorithm="hmac-sha1",headers="date",signature="x"',
                    'Date' => 'x',
                ]
            )
        );

        // assert it works without errors; correctness of results tested elsewhere.
        $this->assertTrue(is_bool($this->noDigestContext->verifier()->isValid($message)));
    }

    public function testSha1Signer()
    {
        $message = new Request('GET', '/path?query=123', ['date' => 'today', 'accept' => 'llamas']);

        $message = $this->sha1context->signer()->sign($message);
        $expectedSha1String = implode(',', [
            'keyId="rsa1"',
            'algorithm="rsa-sha1"',
            'headers="(request-target) date"',
            'signature="YIR3DteE3Jmz1VAnUMTgjTn3vTKfQuZl1CJhMBvGOZpnzwKeYBXA' .
            'H108FojnbSeVG/AXq9pcrA6AFK0peg0aueqxpaFlo+4L/q5XzJ+QoryY3dlSr' .
            'xwVnE5s5M19xmFm/6YkZR/KPeANCsG4SPL82Um/PCEMU0tmKd6sSx+IIzAYbX' .
            'G/VrFMDeQAdXqpU1EhgxopKEAapN8rChb49+1JfR/RxlSKiLukJJ6auurm2zM' .
            'n2D40fR1d2umA5LAO7vRt2iQwVbtwiFkVlRqkMvGftCNZByu8jJ6StI5H7Efu' .
            'ANSHAZXKXWNH8yxpBUW/QCHCZjPd0ugM0QJJIc7i8JbGlA=="',
        ]);

        $this->assertEquals(
            $expectedSha1String,
            $message->getHeader('Signature')[0]
        );
    }

    public function testSha256Signer()
    {
        $message = new Request('GET', '/path?query=123', ['date' => 'today', 'accept' => 'llamas']);

        $message = $this->sha256context->signer()->sign($message);
        $expectedSha256String = implode(',', [
            'keyId="rsa1"',
            'algorithm="rsa-sha256"',
            'headers="(request-target) date"',
            'signature="WGIegQCC3GEwxbkuXtq67CAqeDhkwblxAH2uoDx5kfWurhLRA5WB' .
            'FDA/aktsZAjuUoimG1w4CGxSecziER1ez44PBlHP2fCW4ArLgnQgcjkdN2cOf/g' .
            'j0OVL8s2usG4o4tud/+jjF3nxTxLl3HC+erBKsJakwXbw9kt4Cr028BToVfNXsW' .
            'oMFpv0IjcgBH2V41AVlX/mYBMMJAihBCIcpgAcGrrxmG2gkfvSn09wtTttkGHft' .
            'PIp3VpB53zbemlJS9Yw3tmmHr6cvWSXqQy/bTsEOoQJ2REfn5eiyzsJu3GiOpiI' .
            'LK67i/WH9moltJtlfV57TV72cgYtjWa6yqhtFg=="',
        ]);

        $this->assertEquals(
            $expectedSha256String,
            $message->getHeader('Signature')[0]
        );
    }

    // /**
    //  * @expectedException     \HttpSignatures\Exception
    //  */
    // public function testRsaBadalgorithm()
    // {
    //     $sha224context = new Context([
    //         'keys' => ['rsa1' => TestKeys::rsaPrivateKey],
    //         'algorithm' => 'rsa-sha224',
    //         'headers' => ['(request-target)', 'date'],
    //     ]);
    // }
}
