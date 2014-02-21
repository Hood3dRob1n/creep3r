require 'test/unit'

require 'stringio'

require 'samba/encrypt'

class SambaEncryptTest < Test::Unit::TestCase
  def test_lm_hash
    assert_equal("E52CAC67419A9A224A3B108F3FA6CB6D",
                 Samba::Encrypt.lm_hash("password"))
    assert_equal("E52CAC67419A9A224A3B108F3FA6CB6D",
                 Samba::Encrypt.lm_hash("paSSWOrd"))
    assert_equal("E0C510199CC66ABDE0C510199CC66ABD",
                 Samba::Encrypt.lm_hash("abcdefgabcdefg"))
    assert_equal("FF3750BCC2B22412C2265B23734E0DAC",
                 Samba::Encrypt.lm_hash("SecREt01"))
    begin
      stderr = $stderr
      $stderr = StringIO.new
      assert_equal("E0C510199CC66ABDE0C510199CC66ABD",
                   Samba::Encrypt.lm_hash("abcdefgabcdefg" + "X"))
      assert_equal("E0C510199CC66ABDE0C510199CC66ABD",
                   Samba::Encrypt.lm_hash("abcdefgabcdefg" + "X" * 100))
      assert_equal("password is truncated to 14 characters\n" * 2,
                   $stderr.string)
    ensure
      $stderr = stderr
    end
  end

  def test_ntlm_hash
    assert_equal("8846F7EAEE8FB117AD06BDD830B7586C",
                 Samba::Encrypt.ntlm_hash("password"))
  end

  def test_ntlmgen 
    assert_equal(["E52CAC67419A9A224A3B108F3FA6CB6D", "8846F7EAEE8FB117AD06BDD830B7586C"], 
                 Samba::Encrypt.ntlmgen("password"))
  end

end
