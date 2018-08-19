<?php

namespace HttpSignatures\tests;

use HttpSignatures\KeyStore;

class KeyStoreHmacTest extends \PHPUnit_Framework_TestCase
{
    public function testFetchHmacSuccess()
    {
        $ks = new KeyStore(['hmacsecret' => 'secretkey']);
        $key = $ks->fetch('hmacsecret');
        $this->assertEquals([ 'hmacsecret', 'secretkey', null, null, 'secret'], [
          $key->id, $key->secret, $key->privateKey, $key->certificate, $key->type]);
    }

}
