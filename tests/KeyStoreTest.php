<?php

namespace HttpSignatures\tests;

use HttpSignatures\KeyStore;

class KeyStoreTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @expectedException \HttpSignatures\Exception
     */
    public function testFetchFail()
    {
        $ks = new KeyStore(['id' => 'secret']);
        $key = $ks->fetch('nope');
    }
}
