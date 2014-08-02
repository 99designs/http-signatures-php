<?php

namespace HttpSignatures\Test;

use HttpSignatures\HeaderList;

class HeaderListTest extends \PHPUnit_Framework_TestCase
{
    public function testToString()
    {
        $hl = new HeaderList(array('(request-target)', 'Date'));
        $this->assertEquals('(request-target) date', $hl->string());
    }

    public function testFromStringRoundTripNormalized()
    {
        $hl = HeaderList::fromString('(request-target) Accept');
        $this->assertEquals('(request-target) accept', $hl->string());
    }
}
