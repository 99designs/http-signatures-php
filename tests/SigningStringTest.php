<?php

namespace HttpSignatures\Tests;

use GuzzleHttp\Psr7\Request;
use HttpSignatures\HeaderList;
use HttpSignatures\HttpMessageFactory;
use HttpSignatures\SigningString;
use Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

class SigningStringTest extends \PHPUnit_Framework_TestCase
{
    public function testWithoutQueryString()
    {
        $headerList = new HeaderList(array('(request-target)'));
        $ss = new SigningString($headerList, $this->message('/path'));

        $this->assertEquals(
            "(request-target): get /path",
            $ss->string()
        );
    }

    public function testSigningStringWithOrderedQueryParameters()
    {
        $headerList = new HeaderList(array('(request-target)', 'date'));
        $ss = new SigningString($headerList, $this->message('/path?a=antelope&z=zebra'));

        $this->assertEquals(
            "(request-target): get /path?a=antelope&z=zebra\ndate: Mon, 28 Jul 2014 15:39:13 -0700",
            $ss->string()
        );
    }

    public function testSigningStringWithUnorderedQueryParameters()
    {
        $headerList = new HeaderList(array('(request-target)', 'date'));
        $ss = new SigningString($headerList, $this->message('/path?z=zebra&a=antelope'));

        $this->assertEquals(
            "(request-target): get /path?z=zebra&a=antelope\ndate: Mon, 28 Jul 2014 15:39:13 -0700",
            $ss->string()
        );
    }

    public function testSigningStringWithOrderedQueryParametersSymfonyRequest()
    {
        $headerList = new HeaderList(array('(request-target)', 'date'));
        $ss = new SigningString($headerList, $this->symfonyMessage('/path?a=antelope&z=zebra'));

        $this->assertEquals(
            "(request-target): get /path?a=antelope&z=zebra\ndate: Mon, 28 Jul 2014 15:39:13 -0700",
            $ss->string()
        );
    }

    public function testSigningStringWithUnorderedQueryParametersSymfonyRequest()
    {
        $headerList = new HeaderList(array('(request-target)', 'date'));
        $ss = new SigningString($headerList, $this->symfonyMessage('/path?z=zebra&a=antelope'));

        $this->assertEquals(
            "(request-target): get /path?z=zebra&a=antelope\ndate: Mon, 28 Jul 2014 15:39:13 -0700",
            $ss->string()
        );
    }

    /**
     * @expectedException \HttpSignatures\Exception
     */
    public function testSigningStringErrorForMissingHeader()
    {
        $headerList = new HeaderList(array('nope'));
        $ss = new SigningString($headerList, $this->message('/'));
        $ss->string();
    }

    private function message($path)
    {
        return new Request('GET', $path, ['date' => 'Mon, 28 Jul 2014 15:39:13 -0700']);
    }

    private function symfonyMessage($path)
    {
        $symfonyRequest = SymfonyRequest::create($path, 'GET');
        $symfonyRequest->headers->replace(array('date' => 'Mon, 28 Jul 2014 15:39:13 -0700'));

        $psr7Factory = new HttpMessageFactory();
        $psrRequest = $psr7Factory->createRequest($symfonyRequest);

        return $psrRequest;
    }
}
