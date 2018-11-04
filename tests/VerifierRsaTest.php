<?php

namespace HttpSignatures\tests;

use GuzzleHttp\Psr7\Request;
use HttpSignatures\KeyStore;
use HttpSignatures\Tests\TestKeys;
use HttpSignatures\Verifier;

class VerifierRsaTest extends \PHPUnit_Framework_TestCase
{
    const DATE = 'today';
    const DATE_DIFFERENT = 'Fri, 01 Aug 2014 13:44:33 -0700';

    /**
     * @var Verifier
     */
    private $verifier;

    /**
     * @var Request
     */
    private $message;

    public function setUp()
    {
        $this->verifier = new Verifier(new KeyStore(['rsa1' => TestKeys::rsaCert]));

        $signatureHeader =
            'keyId="rsa1",algorithm="rsa-sha256",headers="(request-target) date",'
            .'signature="WGIegQCC3GEwxbkuXtq67CAqeDhkwblxAH2uoDx5kfWurhLRA5WBFDA/a'
            .'ktsZAjuUoimG1w4CGxSecziER1ez44PBlHP2fCW4ArLgnQgcjkdN2cOf/gj0OVL8s2us'
            .'G4o4tud/+jjF3nxTxLl3HC+erBKsJakwXbw9kt4Cr028BToVfNXsWoMFpv0IjcgBH2V4'
            .'1AVlX/mYBMMJAihBCIcpgAcGrrxmG2gkfvSn09wtTttkGHftPIp3VpB53zbemlJS9Yw3'
            .'tmmHr6cvWSXqQy/bTsEOoQJ2REfn5eiyzsJu3GiOpiILK67i/WH9moltJtlfV57TV72c'
            .'gYtjWa6yqhtFg=="';

        $this->message = new Request('GET', '/path?query=123', [
            'Date' => self::DATE,
            'Signature' => $signatureHeader,
        ]);
    }

    public function testVerifyValidRsaMessage()
    {
        $this->assertTrue($this->verifier->isValid($this->message));
    }

    public function testVerifyValidRsaMessageAuthorizationHeader()
    {
        $message = $this->message->withHeader(
            'Authorization',
            "Signature {$this->message->getHeader('Signature')[0]}"
        );
        $message = $this->message->withoutHeader('Signature');

        $this->assertTrue($this->verifier->isValid($this->message));
    }

    public function testRejectTamperedRsaRequestMethod()
    {
        $message = $this->message->withMethod('POST');
        $this->assertFalse($this->verifier->isValid($message));
    }

    public function testRejectTamperedRsaDate()
    {
        $message = $this->message->withHeader('Date', self::DATE_DIFFERENT);
        $this->assertFalse($this->verifier->isValid($message));
    }

    public function testRejectTamperedRsaSignature()
    {
        $message = $this->message->withHeader(
            'Signature',
            preg_replace('/signature="/', 'signature="x', $this->message->getHeader('Signature')[0])
        );
        $this->assertFalse($this->verifier->isValid($message));
    }

    public function testRejectRsaMessageWithoutSignatureHeader()
    {
        $message = $this->message->withoutHeader('Signature');
        $this->assertFalse($this->verifier->isValid($message));
    }

    public function testRejectRsaMessageWithGarbageSignatureHeader()
    {
        $message = $this->message->withHeader('Signature', 'not="a",valid="signature"');
        $this->assertFalse($this->verifier->isValid($message));
    }

    public function testRejectRsaMessageWithPartialSignatureHeader()
    {
        $message = $this->message->withHeader('Signature', 'keyId="aa",algorithm="bb"');
        $this->assertFalse($this->verifier->isValid($message));
    }

    public function testRejectsRsaMessageWithUnknownKeyId()
    {
        $verifier = new Verifier(new KeyStore(['nope' => 'secret']));
        $this->assertFalse($verifier->isValid($this->message));
    }

    public function testRejectsRsaMessageMissingSignedHeaders()
    {
        $message = $this->message->withoutHeader('Date');
        $this->assertFalse($this->verifier->isValid($message));
    }
}
