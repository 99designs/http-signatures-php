<?php

namespace HttpSignatures\tests;

use HttpSignatures\KeyStore;

class KeyStoreHmacTest extends \PHPUnit_Framework_TestCase
{
    public function testFetchHmacSuccess()
    {
        $ks = new KeyStore(['hmacsecret' => 'ThisIsASecretKey']);
        $key = $ks->fetch('hmacsecret');
        $this->assertEquals([ 'hmacsecret', 'ThisIsASecretKey', 'ThisIsASecretKey', 'secret'], [
          $key->getId(), $key->getVerifyingKey(), $key->getSigningKey(), $key->getType()]);
    }

}
