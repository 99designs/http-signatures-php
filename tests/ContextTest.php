<?php

namespace HttpSignatures\Tests;

use GuzzleHttp\Psr7\Request;
use HttpSignatures\Context;

class ContextTest extends \PHPUnit_Framework_TestCase
{
    private $context;

    public function setUp()
    {
        $this->context = new Context(array(
            'keys' => array('pda' => 'secret'),
            'algorithm' => 'hmac-sha256',
            'headers' => array('(request-target)', 'date'),
        ));
    }

    public function testSigner()
    {
        $message = new Request('GET', '/path?query=123', ['date' => 'today', 'accept' => 'llamas']);
        $message = $this->context->signer()->sign($message);

        $expectedString = implode(',', array(
            'keyId="pda"',
            'algorithm="hmac-sha256"',
            'headers="(request-target) date"',
            'signature="SFlytCGpsqb/9qYaKCQklGDvwgmrwfIERFnwt+yqPJw="',
        ));

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
            'Signature' => 'keyId="pda",algorithm="hmac-sha1",headers="date",signature="x"',
            'Date' => 'x',
        ]));

        // assert it works without errors; correctness of results tested elsewhere.
        $this->assertTrue(is_bool($this->context->verifier()->isValid($message)));
    }
}
