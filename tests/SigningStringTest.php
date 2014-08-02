<?php

namespace HttpSignatures\Test;

use HttpSignatures\HeaderList;
use HttpSignatures\SigningString;
use Symfony\Component\HttpFoundation\Request;

class SigningStringTest extends \PHPUnit_Framework_TestCase
{
    private $message;

    public function setUp()
    {
        $this->message = Request::create('/path?query=123', 'GET');
        $this->message->headers->replace(array('date' => 'Mon, 28 Jul 2014 15:39:13 -0700'));
    }

    public function testSigningString()
    {
        $headerList = new HeaderList(array('(request-target)', 'date'));
        $ss = new SigningString($headerList, $this->message);

        $this->assertEquals(
            "(request-target): get /path?query=123\ndate: Mon, 28 Jul 2014 15:39:13 -0700",
            $ss->string()
        );
    }

    /**
     * @expectedException HttpSignatures\Exception
     */
    public function testSigningStringHandlesDuplicateHeaders()
    {
        $headerList = new HeaderList(array('nope'));
        $ss = new SigningString($headerList, $this->message);
        $ss->string();
    }
}
