# ruby-smbhash

## Description
ruby-smbhash is a implementation of lanman and nt md4 hash functions for use in Samba style smbpasswd entries. It was stripped from ActiveSambaLDAP (http://asl.rubyforge.org/activesambaldap/)

## Usage
    require 'samba/encrypt'

    Samba::Encrypt.lm_hash    "password"
    => "E52CAC67419A9A224A3B108F3FA6CB6D"

    Samba::Encrypt.ntlm_hash  "password"
    => "8846F7EAEE8FB117AD06BDD830B7586C"

    Samba::Encrypt.ntlmgen    "password"
    => ["E52CAC67419A9A224A3B108F3FA6CB6D", "8846F7EAEE8FB117AD06BDD830B7586C"]

## Credits
  * ActiveSambaLDAP project for sharing the code
  * jon-mercer for porting it to ruby 1.9

