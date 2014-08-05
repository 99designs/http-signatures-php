<?php

namespace HttpSignatures\Test;

use HttpSignatures\KeyStore;
use HttpSignatures\Verifier;
use Symfony\Component\HttpFoundation\Request;

class VerifierTest extends \PHPUnit_Framework_TestCase
{
    const DATE = "Fri, 01 Aug 2014 13:44:32 -0700";
    const DATE_DIFFERENT = "Fri, 01 Aug 2014 13:44:33 -0700";

    private $verifier;
    private $message;

    public function setUp()
    {
        $this->setUpVerifier();
        $this->setUpValidMessage();
    }

    private function setUpVerifier()
    {
        $keyStore = new KeyStore(array("pda" => "secret"));
        $this->verifier = new Verifier($keyStore);
    }

    private function setUpValidMessage()
    {
        $signatureHeader = sprintf(
            'keyId="%s",algorithm="%s",headers="%s",signature="%s"',
            "pda",
            "hmac-sha256",
            "(request-target) date",
            "cS2VvndvReuTLy52Ggi4j6UaDqGm9hMb4z0xJZ6adqU="
        );

        $this->message = Request::create('/path?query=123', 'GET');
        $this->message->headers->replace(array(
            "Date" => self::DATE,
            "Signature" => $signatureHeader,
        ));
    }

    public function testVerifyValidMessage()
    {
        $this->assertTrue($this->verifier->isValid($this->message));
    }

    public function testRejectTamperedRequestMethod()
    {
        $this->message->setMethod('POST');
        $this->assertFalse($this->verifier->isValid($this->message));
    }

    public function testRejectTamperedDate()
    {
        $this->message->headers->set('Date', self::DATE_DIFFERENT);
        $this->assertFalse($this->verifier->isValid($this->message));
    }

    public function testRejectTamperedSignature()
    {
        $this->message->headers->set(
            'Signature',
            preg_replace('/signature="/', 'signature="x', $this->message->headers->get('Signature'))
        );
        $this->assertFalse($this->verifier->isValid($this->message));
    }

    public function testRejectMessageWithoutSignatureHeader()
    {
        $this->message->headers->remove('Signature');
        $this->assertFalse($this->verifier->isValid($this->message));
    }

    public function testRejectMessageWithGarbageSignatureHeader()
    {
        $this->message->headers->set('Signature', 'not="a",valid="signature"');
        $this->assertFalse($this->verifier->isValid($this->message));
    }

    public function testRejectMessageWithPartialSignatureHeader()
    {
        $this->message->headers->set('Signature', 'keyId="aa",algorithm="bb"');
        $this->assertFalse($this->verifier->isValid($this->message));
    }

    public function testRejectsMessageWithUnknownKeyId()
    {
        $keyStore = new KeyStore(array("nope" => "secret"));
        $verifier = new Verifier($keyStore);
        $this->assertFalse($verifier->isValid($this->message));
    }

    public function testRejectsMessageMissingSignedHeaders()
    {
        $this->message->headers->remove('Date');
        $this->assertFalse($this->verifier->isValid($this->message));
    }
}
