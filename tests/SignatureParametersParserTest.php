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

    /**
     * @expectedException \HttpSignatures\SignatureParseException
     */
    public function testParseThrowsTypedException()
    {
        $parser = new SignatureParametersParser('nope');
        $parser->parse();
    }

    /**
     * @expectedException \HttpSignatures\SignatureParseException
     */
    public function testParseExceptionForMissingComponents()
    {
        $parser = new SignatureParametersParser(
            'keyId="example",algorithm="hmac-sha1",headers="(request-target) date"'
        );
        $parser->parse();
    }
}
