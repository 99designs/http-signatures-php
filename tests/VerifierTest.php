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
    private $signedMessage;

    /**
     * @var Request
     */
    private $authorizedMessage;

    public function setUp()
    {
        $this->setUpVerifier();
        $this->setUpValidSignedMessage();
        $this->setUpValidAuthorizedMessage();
    }

    private function setUpVerifier()
    {
        $keyStore = new KeyStore(['pda' => 'secret']);
        $this->verifier = new Verifier($keyStore);
    }

    private function setUpValidSignedMessage()
    {
        $signatureHeader = sprintf(
            'keyId="%s",algorithm="%s",headers="%s",signature="%s"',
            'pda',
            'hmac-sha256',
            '(request-target) date',
            'cS2VvndvReuTLy52Ggi4j6UaDqGm9hMb4z0xJZ6adqU='
        );

        $this->signedMessage = new Request('GET', '/path?query=123', [
            'Date' => self::DATE,
            'Signature' => $signatureHeader,
            'Authorization' => 'Bearer abc123',
        ]);
    }

    private function setUpValidAuthorizedMessage()
    {
        $authorizationHeader = sprintf(
            'Signature keyId="%s",algorithm="%s",headers="%s",signature="%s"',
            'pda',
            'hmac-sha256',
            '(request-target) date',
            'cS2VvndvReuTLy52Ggi4j6UaDqGm9hMb4z0xJZ6adqU='
        );

        $this->authorizedMessage = new Request('GET', '/path?query=123', [
            'Date' => self::DATE,
            'Authorization' => $authorizationHeader,
            'Signature' => 'My Lawyer signed this',
        ]);
    }

    public function testVerifyValidMessageSignatureHeader()
    {
        $this->assertTrue($this->verifier->isSigned($this->signedMessage));
    }

    public function testVerifyValidMessageAuthorizationHeader()
    {
        // $message = $this->message->withHeader('Authorization', "Signature {$this->message->getHeader('Signature')[0]}");
        // $message = $message->withoutHeader('Signature');
        $this->assertTrue($this->verifier->isAuthorized($this->authorizedMessage));
    }

    public function testRejectOnlySignatureHeaderAsAuthorized()
    {
        $this->assertFalse($this->verifier->isAuthorized($this->signedMessage));
    }

    public function testRejectOnlyAuthorizationHeaderAsSigned()
    {
        $this->assertFalse($this->verifier->isSigned($this->authorizedMessage));
    }

    public function testRejectTamperedRequestMethod()
    {
        $message = $this->signedMessage->withMethod('POST');
        $this->assertFalse($this->verifier->isSigned($message));
    }

    public function testRejectTamperedDate()
    {
        $message = $this->signedMessage->withHeader('Date', self::DATE_DIFFERENT);
        $this->assertFalse($this->verifier->isSigned($message));
    }

    public function testRejectTamperedSignature()
    {
        $message = $this->signedMessage->withHeader(
            'Signature',
            preg_replace('/signature="/', 'signature="x', $this->signedMessage->getHeader('Signature')[0])
        );
        $this->assertFalse($this->verifier->isSigned($message));
    }

    public function testRejectMessageWithoutSignatureHeader()
    {
        $message = $this->signedMessage->withoutHeader('Signature');
        $this->assertFalse($this->verifier->isSigned($message));
    }

    public function testRejectMessageWithGarbageSignatureHeader()
    {
        $message = $this->signedMessage->withHeader('Signature', 'not="a",valid="signature"');
        $this->assertFalse($this->verifier->isSigned($message));
    }

    public function testRejectMessageWithPartialSignatureHeader()
    {
        $message = $this->signedMessage->withHeader('Signature', 'keyId="aa",algorithm="bb"');
        $this->assertFalse($this->verifier->isSigned($message));
    }

    public function testRejectsMessageWithUnknownKeyId()
    {
        $keyStore = new KeyStore(['nope' => 'secret']);
        $verifier = new Verifier($keyStore);
        $this->assertFalse($verifier->isSigned($this->signedMessage));
    }

    public function testRejectsMessageMissingSignedHeaders()
    {
        $message = $this->signedMessage->withoutHeader('Date');
        $this->assertFalse($this->verifier->isSigned($message));
    }
}
