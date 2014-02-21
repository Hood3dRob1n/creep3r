module Samba
  module Encrypt
    module Builder18
      module_function

      def str_to_key(str)
        key = "\000" * 8
        key[0] = str[0] >> 1;
        key[1] = ((str[0] & 0x01) << 6) | (str[1] >> 2);
        key[2] = ((str[1] & 0x03) << 5) | (str[2] >> 3);
        key[3] = ((str[2] & 0x07) << 4) | (str[3] >> 4);
        key[4] = ((str[3] & 0x0F) << 3) | (str[4] >> 5);
        key[5] = ((str[4] & 0x1F) << 2) | (str[5] >> 6);
        key[6] = ((str[5] & 0x3F) << 1) | (str[6] >> 7);
        key[7] = str[6] & 0x7F;

        key.size.times do |i|
          key[i] = (key[i] << 1);
        end

        key
      end
    end
  end
end
