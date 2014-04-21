require 'openssl'

module Samba
  module Encrypt
    module_function
    def lm_hash(password, encoding=nil)
      dos_password = Private.convert_encoding("ISO-8859-1",
                                              encoding || "UTF-8",
                                              password.upcase)
      if dos_password.size > 14
        warn("\r[*] Password truncated to 14 characters for LM hashing") #Suppressed as its not needed and should be known by users, its stated in readme
        dos_password = dos_password[0, 14]
      end
      Private.encrypt_14characters(dos_password).unpack("C*").collect do |char|
        "%02X" % char
      end.join
    end

    def ntlm_hash(password, encoding=nil)
      ucs2_password = Private.convert_encoding("UCS-2",
                                               encoding || "UTF-8",
                                               password)
      if ucs2_password.size > 256
        raise ArgumentError.new("must be <= 256 characters in UCS-2")
      end
      hex = OpenSSL::Digest::MD4.new(ucs2_password).hexdigest.upcase
      hex
    end

    def ntlmgen(password, encoding=nil)    
      [
        lm_hash(password, encoding),
        ntlm_hash(password, encoding)
      ]
    end

    module Private
      module_function

      if /^1\.9/ =~ RUBY_VERSION
        #Minor edit to original path to work for us
        require "#{HOME}classes/ruby-smbhash/lib/samba/builder19"
        Builder = Builder19
      elsif /^1\.8/ =~ RUBY_VERSION
        #Minor edit to original path to work for us
        require "#{HOME}classes/ruby-smbhash/lib/samba/builder18"
        Builder = Builder18
      else
        raise NotImplementedError
      end

      def convert_encoding(to, from, str)
        if same_encoding?(to, from)
          str
        else
	  # Minor patching to suppress deprecation warning thrown in 1.9+ when using iconv
	  ####################################
	  oldverb = $VERBOSE; $VERBOSE = nil #
	  require 'iconv'                    #
	  $VERBOSE = oldverb                 #
	  ####################################
          Iconv.iconv(to, from, str).join
        end
      end

      def normalize_encoding(encoding)
        encoding.downcase.gsub(/-/, "_")
      end

      def same_encoding?(a, b)
        na = normalize_encoding(a)
        nb = normalize_encoding(b)
        na == nb or na.gsub(/_/, '') == nb.gsub(/_/, '')
      end

      def des_crypt56(input, key_str, forward_only)
        key = Builder::str_to_key(key_str)
        encoder = OpenSSL::Cipher::DES.new
        encoder.encrypt
        encoder.key = key
        encoder.update(input)
      end

      LM_MAGIC = "KGS!@\#$%"
      def encrypt_14characters(chars)
        raise ArgumentError.new("must be <= 14 characters") if chars.size > 14
        chars = chars.to_s.ljust(14, "\000")
        des_crypt56(LM_MAGIC, chars[0, 7], true) +
            des_crypt56(LM_MAGIC, chars[7, 7], true)
      end
    end
  end
end
