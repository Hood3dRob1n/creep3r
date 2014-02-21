module Samba
  module Encrypt
    module Builder19
      module_function

      def str_to_key(str)
        key = "\000" * 8
        key.setbyte(0,  str.getbyte(0) >> 1);
        key.setbyte(1,  ((str.getbyte(0) & 0x01) << 6) | (str.getbyte(1) >> 2));
        key.setbyte(2,  ((str.getbyte(1) & 0x03) << 5) | (str.getbyte(2) >> 3));
        key.setbyte(3,  ((str.getbyte(2) & 0x07) << 4) | (str.getbyte(3) >> 4));
        key.setbyte(4,  ((str.getbyte(3) & 0x0F) << 3) | (str.getbyte(4) >> 5));
        key.setbyte(5,  ((str.getbyte(4) & 0x1F) << 2) | (str.getbyte(5) >> 6));
        key.setbyte(6,  ((str.getbyte(5) & 0x3F) << 1) | (str.getbyte(6) >> 7));
        key.setbyte(7,  str.getbyte(6) & 0x7F);

        key.size.times do |i|
          key.setbyte(i, (key.getbyte(i) << 1));
        end

        key
      end
    end
  end
end
