<?php

namespace HttpSignatures\Test;

use HttpSignatures\HeaderList;

class HeaderListTest extends \PHPUnit_Framework_TestCase
{
    public function testToString()
    {
        $hl = new HeaderList(array('(request-target)', 'Date'));
        $this->assertEquals('(request-target) date', (string)$hl);
    }
}
