<?php

namespace HttpSignatures\tests;

use HttpSignatures\SignatureParametersParser;
use PHPUnit\Framework\TestCase;

class SignatureParametersParserTest extends TestCase
{
    public function testParseReturnsExpectedAssociativeArray()
    {
        $parser = new SignatureParametersParser(
            'keyId="example",algorithm="hmac-sha1",headers="(request-target) date",signature="b64"'
        );
        $this->assertEquals(
            [
                'keyId' => 'example',
                'algorithm' => 'hmac-sha1',
                'headers' => '(request-target) date',
                'signature' => 'b64',
            ],
            $parser->parse()
        );
    }

    public function testParseThrowsTypedException()
    {
        $this->expectException(\HttpSignatures\SignatureParseException::class);
        $parser = new SignatureParametersParser('nope');
        $parser->parse();
    }

    public function testParseExceptionForMissingComponents()
    {
        $this->expectException(\HttpSignatures\SignatureParseException::class);
        $parser = new SignatureParametersParser(
            'keyId="example",algorithm="hmac-sha1",headers="(request-target) date"'
        );
        $parser->parse();
    }
}
