<?php

namespace HttpSignatures\Test;

use HttpSignatures\Context;
use Symfony\Component\HttpFoundation\Request;

class ContextTest extends \PHPUnit_Framework_TestCase
{
    public function testSigner()
    {
        $context = new Context(array(
            'keys' => array('pda' => 'secret'),
            'algorithm' => 'hmac-sha256',
            'headers' => array('(request-target)', 'date'),
        ));

        $message = Request::create('/path?query=123', 'GET');
        $message->headers->replace(array('date' => 'today', 'accept' => 'llamas'));

        $context->signer()->sign($message);

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
}
