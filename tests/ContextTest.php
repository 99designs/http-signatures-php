<?php

namespace HttpSignatures\Test;

use HttpSignatures\Context;
use Symfony\Component\HttpFoundation\Request;

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
        $message = Request::create('/path?query=123', 'GET');
        $message->headers->replace(array('date' => 'today', 'accept' => 'llamas'));

        $this->context->signer()->sign($message);

        $expectedString = implode(',', array(
            'keyId="pda"',
            'algorithm="hmac-sha256"',
            'headers="(request-target) date"',
            'signature="SFlytCGpsqb/9qYaKCQklGDvwgmrwfIERFnwt+yqPJw="',
        ));

        $this->assertEquals(
            $expectedString,
            $message->headers->get('Signature')
        );

        $this->assertEquals(
            'Signature ' . $expectedString,
            $message->headers->get('Authorization')
        );
    }

    public function testVerifier()
    {
        $message = Request::create('/path?query=123', 'GET');
        $message->headers->replace(array(
            'Signature' => 'keyId="pda",algorithm="hmac-sha1",headers="date",signature="x"',
            'Date' => 'x',
        ));
        // assert it works without errors; correctness of results tested elsewhere.
        $this->assertTrue(is_bool($this->context->verifier()->isValid($message)));
    }
}
