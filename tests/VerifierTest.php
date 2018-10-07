<?php

namespace HttpSignatures\tests;

use GuzzleHttp\Psr7\Request;
use HttpSignatures\KeyStore;
use HttpSignatures\Verifier;

class VerifierTest extends \PHPUnit_Framework_TestCase
{
    const DATE = 'Fri, 01 Aug 2014 13:44:32 -0700';
    const DATE_DIFFERENT = 'Fri, 01 Aug 2014 13:44:33 -0700';

    /**
     * @var Verifier
     */
    private $verifier;

    /**
     * @var Request
     */
    private $validMessage;

    /**
     * @var Request
     */
    private $validMessageNoHeaders;

    public function setUp()
    {
        $this->setUpVerifier();
        $this->setUpValidMessage();
        $this->setUpValidMessageNoHeaders();
    }

    private function setUpVerifier()
    {
        $keyStore = new KeyStore(['pda' => 'secret']);
        $this->verifier = new Verifier($keyStore);
    }

    private function setUpValidMessage()
    {
        $signatureHeader = sprintf(
            'keyId="%s",algorithm="%s",headers="%s",signature="%s"',
            'pda',
            'hmac-sha256',
            '(request-target) date',
            'cS2VvndvReuTLy52Ggi4j6UaDqGm9hMb4z0xJZ6adqU='
        );

        $this->validMessage = new Request('GET', '/path?query=123', [
            'Date' => self::DATE,
            'Signature' => $signatureHeader,
        ]);
    }

    private function setUpValidMessageNoHeaders()
    {
        $signatureHeaderNoHeaders = sprintf(
            'keyId="%s",algorithm="%s",signature="%s"',
            'pda',
            'hmac-sha256',
            'SNERdFCcPF40c5kw0zbmSXn3Zv2KZWhiuHSijhZs/4k='
        );

        $this->validMessageNoHeaders = new Request('GET', '/path?query=123', [
            'Date' => 'today',
            'Signature' => $signatureHeaderNoHeaders,
            'NoSignatureHeaders' => 'true',
        ]);
    }

    public function testVerifyValidMessage()
    {
        $this->assertTrue($this->verifier->isValid($this->validMessage));
    }

    public function testVerifyValidMessageNoHeaders()
    {
        $this->assertTrue($this->verifier->isValid($this->validMessageNoHeaders));
    }

    public function testVerifyValidMessageAuthorizationHeader()
    {
        $message = $this->validMessage->withHeader(
          'Authorization',
          'Signature '.$this->validMessage->getHeader('Signature')[0]
          );
        $message = $message->withoutHeader('Signature');

        $this->assertTrue($this->verifier->isValid($this->validMessage));
    }

    public function testRejectTamperedRequestMethod()
    {
        $message = $this->validMessage->withMethod('POST');
        $this->assertFalse($this->verifier->isValid($message));
    }

    public function testRejectTamperedDate()
    {
        $message = $this->validMessage->withHeader('Date', self::DATE_DIFFERENT);
        $this->assertFalse($this->verifier->isValid($message));
    }

    public function testRejectTamperedSignature()
    {
        $message = $this->validMessage->withHeader(
            'Signature',
            preg_replace('/signature="/', 'signature="x', $this->validMessage->getHeader('Signature')[0])
        );
        $this->assertFalse($this->verifier->isValid($message));
    }

    public function testRejectMessageWithoutSignatureHeader()
    {
        $message = $this->validMessage->withoutHeader('Signature');
        $this->assertFalse($this->verifier->isValid($message));
    }

    public function testRejectMessageWithGarbageSignatureHeader()
    {
        $message = $this->validMessage->withHeader('Signature', 'not="a",valid="signature"');
        $this->assertFalse($this->verifier->isValid($message));
    }

    public function testRejectMessageWithPartialSignatureHeader()
    {
        $message = $this->validMessage->withHeader('Signature', 'keyId="aa",algorithm="bb"');
        $this->assertFalse($this->verifier->isValid($message));
    }

    public function testRejectsMessageWithUnknownKeyId()
    {
        $keyStore = new KeyStore(['nope' => 'secret']);
        $verifier = new Verifier($keyStore);
        $this->assertFalse($verifier->isValid($this->validMessage));
    }

    public function testRejectsMessageMissingSignedHeaders()
    {
        $message = $this->validMessage->withoutHeader('Date');
        $this->assertFalse($this->verifier->isValid($message));
    }
}
