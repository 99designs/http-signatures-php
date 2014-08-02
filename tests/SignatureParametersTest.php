<?php

namespace HttpSignatures\Test;

use HttpSignatures\HmacAlgorithm;
use HttpSignatures\HeaderList;
use HttpSignatures\Key;
use HttpSignatures\SignatureParameters;

class SignatureParametersTest extends \PHPUnit_Framework_TestCase
{
    public function testToString()
    {
        $key = new Key('pda', 'secret');
        $algorithm = new HmacAlgorithm('sha256');
        $headerList = new HeaderList(array('(request-target)', 'date'));

        $signature = $this->getMockBuilder('HttpSignatures\Signature')
            ->disableOriginalConstructor()
            ->getMock();

        $signature
            ->expects($this->any())
            ->method('string')
            ->will($this->returnValue('thesignature'));

        $sp = new SignatureParameters($key, $algorithm, $headerList, $signature);

        $this->assertEquals(
            'keyId="pda",algorithm="hmac-sha256",headers="(request-target) date",signature="dGhlc2lnbmF0dXJl"',
            $sp->string()
        );
    }
}
