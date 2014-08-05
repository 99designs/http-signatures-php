<?php

namespace HttpSignatures\Test;

use HttpSignatures\SignatureParametersParser;

class SignatureParametersParserTest extends \PHPUnit_Framework_TestCase
{
    public function testParseReturnsExpectedAssociativeArray()
    {
        $parser = new SignatureParametersParser(
            'keyId="example",algorithm="hmac-sha1",headers="(request-target) date",signature="b64"'
        );
        $this->assertEquals(
            array(
                'keyId' => 'example',
                'algorithm' => 'hmac-sha1',
                'headers' => '(request-target) date',
                'signature' => 'b64',
            ),
            $parser->parse()
        );
    }

    /**
     * @expectedException HttpSignatures\SignatureParseException
     */
    public function testParseThrowsTypedException()
    {
        $parser = new SignatureParametersParser('nope');
        $parser->parse();
    }

    /**
     * @expectedException HttpSignatures\SignatureParseException
     */
    public function testParseExceptionForMissingComponents()
    {
        $parser = new SignatureParametersParser(
            'keyId="example",algorithm="hmac-sha1",headers="(request-target) date"'
        );
        $parser->parse();
    }
}
