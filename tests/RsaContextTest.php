<?php

namespace HttpSignatures\tests;

use GuzzleHttp\Psr7\Request;
use HttpSignatures\Context;
use HttpSignatures\Tests\TestKeys;

class RsaContextTest extends \PHPUnit_Framework_TestCase
{
    private $context;

    public function setUp()
    {
        $this->context = new Context([
            'keys' => ['rsa1' => TestKeys::rsaKey],
            'algorithm' => 'rsa-sha1',
            'headers' => ['(request-target)', 'date'],
        ]);
    }

    public function testSigner()
    {
        $message = new Request('GET', '/path?query=123', ['date' => 'today', 'accept' => 'llamas']);
        $message = $this->context->signer()->sign($message);

        $expectedString = implode(',', [
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
            $expectedString,
            $message->getHeader('Signature')[0]
        );

        $this->assertEquals(
            'Signature ' . $expectedString,
            $message->getHeader('Authorization')[0]
        );
    }

    public function testVerifier()
    {
        $message = $this->context->signer()->sign(new Request('GET', '/path?query=123', [
            'Signature' => 'keyId="rsa1",algorithm="rsa-sha1",headers="date",signature="x"',
            'Date' => 'x',
        ]));

        // assert it works without errors; correctness of results tested elsewhere.
        $this->assertTrue(is_bool($this->context->verifier()->isValid($message)));
    }
}
