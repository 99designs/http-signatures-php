<?php

namespace HttpSignatures\Test;

use HttpSignatures\HeaderList;
use HttpSignatures\SigningString;
use Symfony\Component\HttpFoundation\Request;

class SigningStringTest extends \PHPUnit_Framework_TestCase
{
    private $message;

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

    /**
     * @expectedException HttpSignatures\Exception
     */
    public function testSigningStringErrorForMissingHeader()
    {
        $headerList = new HeaderList(array('nope'));
        $ss = new SigningString($headerList, $this->message('/'));
        $ss->string();
    }

    private function message($path)
    {
        $m = Request::create($path, 'GET');
        $m->headers->replace(array('date' => 'Mon, 28 Jul 2014 15:39:13 -0700'));
        return $m;
    }
}
