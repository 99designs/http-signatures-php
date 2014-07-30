<?php

namespace HttpSignatures\Test;

use HttpSignatures\Context;

class ContextTest extends \PHPUnit_Framework_TestCase
{
    public function testSigner()
    {
        $context = new Context(array(
            'keys' => array('id' => 'secret'),
            'algorithm' => 'hmac-sha256',
            'headers' => array('(request-target)', 'date'),
        ));

        $this->assertInstanceOf(
            'HttpSignatures\\Signer',
            $context->signer()
        );
    }
}
