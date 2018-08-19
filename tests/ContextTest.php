<?php

namespace HttpSignatures\tests;

use GuzzleHttp\Psr7\Request;
use HttpSignatures\Context;

class ContextTest extends \PHPUnit_Framework_TestCase
{
    private $context;

    public function setUp()
    {
        $this->noDigestContext = new Context([
            'keys' => ['pda' => 'secret'],
            'algorithm' => 'hmac-sha256',
            'headers' => ['(request-target)', 'date'],
        ]);
        $this->withDigestContext = new Context([
            'keys' => ['pda' => 'secret'],
            'algorithm' => 'hmac-sha256',
            'headers' => ['(request-target)', 'date', 'digest'],
        ]);
    }

    public function testSignerNoDigestAction()
    {
        $message = new Request('GET', '/path?query=123', ['date' => 'today', 'accept' => 'llamas']);
        $message = $this->noDigestContext->signer()->sign($message);

        $expectedString = implode(',', [
            'keyId="pda"',
            'algorithm="hmac-sha256"',
            'headers="(request-target) date"',
            'signature="SFlytCGpsqb/9qYaKCQklGDvwgmrwfIERFnwt+yqPJw="',
        ]);

        $this->assertEquals(
            $expectedString,
            $message->getHeader('Signature')[0]
        );

        $this->assertEquals(
            'Signature ' . $expectedString,
            $message->getHeader('Authorization')[0]
        );
    }

    public function testSignerAddDigestToHeadersList()
    {
        $message = new Request(
            'GET', '/path?query=123',
            ['date' => 'today', 'accept' => 'llamas'],
            'This is a body');
        $message = $this->noDigestContext->signer()->sign($message, true);

        $expectedString = implode(',', [
            'keyId="pda"',
            'algorithm="hmac-sha256"',
            'headers="(request-target) date digest"',
            'signature="XihRwDYmFZCLX7us8S+ScqTLo8glcPgm5WXNRxUN9xs="']);
        $expectedDigestHeader =
          'SHA-256=8qVirT1Mv9ZqQhA8DrGKEvIIPPm7HmhQ0Hl4UFTBfsQ=';

        $this->assertEquals(
            $expectedString,
            $message->getHeader('Signature')[0]
        );

        $this->assertEquals(
            $expectedDigestHeader,
            $message->getHeader('Digest')[0]
        );

        $this->assertEquals(
            'Signature ' . $expectedString,
            $message->getHeader('Authorization')[0]
        );
    }

    public function testSignerReplaceDigest()
    {
        $message = new Request(
            'GET', '/path?query=123',
              ['date' => 'today',
              'accept' => 'llamas',
              'Digest' => 'SHA-256=E/P+4y4x6EySO9qNAjCtQKxVwE1xKsNI/k+cjK+vtLU='],
            'This is a body');
        $message = $this->noDigestContext->signer()->sign($message, true);

        $expectedString = implode(',', [
            'keyId="pda"',
            'algorithm="hmac-sha256"',
            'headers="(request-target) date digest"',
            'signature="XihRwDYmFZCLX7us8S+ScqTLo8glcPgm5WXNRxUN9xs="']);
        $expectedDigestHeader =
          'SHA-256=8qVirT1Mv9ZqQhA8DrGKEvIIPPm7HmhQ0Hl4UFTBfsQ=';

        $this->assertEquals(
            $expectedString,
            $message->getHeader('Signature')[0]
        );

        $this->assertEquals(
            $expectedDigestHeader,
            $message->getHeader('Digest')[0]
        );

        $this->assertEquals(
            'Signature ' . $expectedString,
            $message->getHeader('Authorization')[0]
        );
    }

    public function testSignerNewDigestIsInHeaderList()
    {
        $message = new Request(
            'GET', '/path?query=123',
              ['date' => 'today',
              'accept' => 'llamas'],
            'This is a body');
        $message = $this->withDigestContext->signer()->sign($message, true);

        $expectedString = implode(',', [
            'keyId="pda"',
            'algorithm="hmac-sha256"',
            'headers="(request-target) date digest"',
            'signature="XihRwDYmFZCLX7us8S+ScqTLo8glcPgm5WXNRxUN9xs="']);
        $expectedDigestHeader =
          'SHA-256=8qVirT1Mv9ZqQhA8DrGKEvIIPPm7HmhQ0Hl4UFTBfsQ=';

        $this->assertEquals(
            $expectedString,
            $message->getHeader('Signature')[0]
        );

        $this->assertEquals(
            $expectedDigestHeader,
            $message->getHeader('Digest')[0]
        );

        $this->assertEquals(
            'Signature ' . $expectedString,
            $message->getHeader('Authorization')[0]
        );
    }
    public function testVerifier()
    {
        $message = $this->noDigestContext->signer()->sign(new Request('GET', '/path?query=123', [
            'Signature' => 'keyId="pda",algorithm="hmac-sha1",headers="date",signature="x"',
            'Date' => 'x',
        ]));

        // assert it works without errors; correctness of results tested elsewhere.
        $this->assertTrue(is_bool($this->noDigestContext->verifier()->isValid($message)));
    }
}
