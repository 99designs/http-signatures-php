<?php

namespace HttpSignatures\tests;

use HttpSignatures\HeaderList;
use HttpSignatures\HmacAlgorithm;
use HttpSignatures\Key;
use HttpSignatures\SignatureParameters;
use PHPUnit\Framework\TestCase;

class SignatureParametersTest extends TestCase
{
    public function testToString()
    {
        $key = new Key('pda', 'secret');
        $algorithm = new HmacAlgorithm('sha256');
        $headerList = new HeaderList(['(request-target)', 'date']);

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
