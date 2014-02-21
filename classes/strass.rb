# String Assistant Tool
# Aides in manual manipulations of strings

def strass_menu_help
  puts "Available Options for the String Assistant Menu: ".underline.white
  puts "back ".light_yellow + "        => ".white + "Return to Main Menu".light_red
  puts "show basic ".light_yellow + "  => ".white + "Show Basic Functions".light_red
  puts "show build ".light_yellow + "  => ".white + "Show Builder Functions".light_red
  puts "show tamper ".light_yellow + " => ".white + "Show Tamper Functions".light_red
  puts "show append ".light_yellow + " => ".white + "Show Append Functions".light_red
  puts "show space ".light_yellow + "  => ".white + "Show Whitespace Functions".light_red
  puts "show comma ".light_yellow + "  => ".white + "Show Comma Functions".light_red
  puts "show floor ".light_yellow + "  => ".white + "Show Floor() Functions".light_red
  print_line("")
end

def strass_menu
  puts
  prompt = "(StrASS)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^!(.+)/
      cmd=$1.strip.chomp
      res = commandz(cmd)
      print_line("\n#{res.join().chomp}")
      strass_menu
    when /^c$|^clear$|^cls$/i
      cls
      banner
      strass_menu
    when /^h$|^help$|^ls$/i
      strass_menu_help
      strass_menu
    when /^exit$|^quit$|^back$/i
      puts
      print_error("Returning to Main Menu....")
      main_menu
    when /^local$|^OS$/i
      local_shell
      strass_menu
    when  /^ip$/i
      ip_info
      strass_menu
    when /^ip2host$|^host2ip$/i
      host = Readline.readline("   Target IP or Domain: ", true)
      dnsenum = DNSEnum.new(host.strip.chomp)
      ip, domain, hostname = dnsenum.host_info
      puts
      print_status("IP: #{ip}")
      print_status("Domain: #{domain}") unless domain == ip
      print_status("Hostname: #{hostname}\n\n")
      strass_menu
    when /^show basic|^showbasics/i
      strass_real_usage(1)
      strass_menu
    when /^show build|^showbuild/i
      strass_real_usage(2)
      strass_menu
    when /^show tamper|^showtamper/i
      strass_real_usage(3)
      strass_menu
    when /^show append|^showappend/i
      strass_real_usage(4)
      strass_menu
    when /^show space|^showspace/i
      strass_real_usage(5)
      strass_menu
    when /^show floor|^showfloor/i
      strass_real_usage(6)
      strass_menu
    when /^show comma|^show commas/i
      strass_real_usage(7)
      strass_menu
    when /^show all|^showall/i
      strass_real_usage(8)
      strass_menu
    when /^union (\d+)/i
      num=$1
      u = union_str(num)
      print_good("#{u}")
      strass_menu
    when /^union_null (\d+)/i
      num=$1
      u = union_null_str(num)
      print_good("#{u}")
      strass_menu
    when /^union_cust (.+) (\d+)/i
      custom=$1
      num=$2
      u = union_expand_str(custom, num)
      print_good("#{u}")
      strass_menu
    when /^union_bof (\d+) (\d+)/i
      size=$1
      num=$2
      u = union_bof_str(size, num)
      print_good("#{u}")
      strass_menu
    when /^ascii (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.asciime}\n")
      strass_menu
    when /^b64 (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.b64e.chomp}\n")
      strass_menu
    when /^b64d (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.b64d}\n")
      strass_menu
    when /^hex (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.hexme}\n")
      strass_menu
    when /^unhex (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.dehexme}\n")
      strass_menu
    when /^mysqlhex (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.mysqlhex}\n")
      strass_menu
    when /^mysqlunhex (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.mysqlhexdecode}\n")
      strass_menu
    when /^mysqlchar (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.mysqlchar}\n")
      strass_menu
    when /^mssqlchar (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.mssqlchar}\n")
      strass_menu
    when /^oraclechar (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.oraclechar}\n")
      strass_menu
    when /^rot13 (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.rot13}\n")
      strass_menu
    when /^unicode (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.unicode}\n")
      strass_menu
    when /^urienc (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.urienc}\n")
      strass_menu
    when /^uridec (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.uridec}\n")
      strass_menu
    when /^doubleurl (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.doubleurl}\n")
      strass_menu
    when /^ent_dec (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.ent_dec}\n")
      strass_menu
    when /^ent_ddec (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.ent_ddec}\n")
      strass_menu
    when /^ent_hex (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.ent_hex}\n")
      strass_menu
    when /^ent_dhex (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.ent_dhex}\n")
      strass_menu
    when /^ent_name (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.ent_name}\n")
      strass_menu
    when /^ent_dname (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.ent_dname}\n")
      strass_menu
    when /^rev (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.reverse}\n")
      strass_menu
    when /^up (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.upcase}\n")
      strass_menu
    when /^down (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.downcase}\n")
      strass_menu
    when /^wafcap (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.wafcap}\n")
      strass_menu
    when /^wafcap_common (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.wafcap_common}\n")
      strass_menu
    when /^doubleup (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.keywords_doubleup}\n")
      strass_menu
    when /^comment (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.comment_keywords}\n")
      strass_menu
    when /^mycomment (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.mysql_comment_keywords}\n")
      strass_menu
    when /^zerocomment (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.mysql_zero_version_comment_keywords}\n")
      strass_menu
    when /^randcomment (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.mysql_random_keywords_comment}\n")
      strass_menu
    when /^mykeyhex (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.hex_encode_keywords}\n")
      strass_menu
    when /^modsec_vers (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.mysql_modsec_versioned_comment}\n")
      strass_menu
    when /^modsec_zerovers (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.mysql_modsec_zero_version_comment}\n")
      strass_menu
    when /^securesphere (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.securesphere}\n")
      strass_menu
    when /^bluecoat (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.bluecoat}\n")
      strass_menu
    when /^equal2like (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.equal2like}\n")
      strass_menu
    when /^gt2between (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.gt2between}\n")
      strass_menu
    when /^percent (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.percent}\n")
      strass_menu
    when /^singleq2utf (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.singleq2utf}\n")
      strass_menu
    when /^singleq2null (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.singleq2null}\n")
      strass_menu
    when /^unmagicquotes (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.unmagicquotes}\n")
      strass_menu
    when /^addnull (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.addnull}\n")
      strass_menu
    when /^adddash (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.adddash}\n")
      strass_menu
    when /^addsdash (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.addsdash}\n")
      strass_menu
    when /^addhash (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.addhash}\n")
      strass_menu
    when /^addcomm (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.addcomm}\n")
      strass_menu
    when /^addsp (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.addsp}\n")
      strass_menu
    when /^space2comment (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.space2comment}\n")
      strass_menu
    when /^space2mycomment (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.space2mycomment}\n")
      strass_menu
    when /^space2dash (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.space2dash}\n")
      strass_menu
    when /^space2dashline (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.space2dashline}\n")
      strass_menu
    when /^space2hash (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.space2hash}\n")
      strass_menu
    when /^space2hashline (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.space2hashline}\n")
      strass_menu
    when /^space2mssql (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.space2mssql}\n")
      strass_menu
    when /^space2mysql (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.space2mysql}\n")
      strass_menu
    when /^space2rand (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.space2rand}\n")
      strass_menu
    when /^space2oa (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.space2oa}\n")
      strass_menu
    when /^space2o9 (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.space2o9}\n")
      strass_menu
    when /^space2ob (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.space2ob}\n")
      strass_menu
    when /^space2oc (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.space2oc}\n")
      strass_menu
    when /^space2od (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.space2od}\n")
      strass_menu
    when /^space2plus (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.space2plus}\n")
      strass_menu
    when /^floor2xor (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.floor2xor}\n")
      strass_menu
    when /^floor2greatest (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.floor2greatest}\n")
      strass_menu
    when /^floor2div (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.floor2div}\n")
      strass_menu
    when /^floor2round (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.floor2round}\n")
      strass_menu
    when /^floor2rand (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.floor2rand}\n")
      strass_menu
    when /^comma2comm (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.comma2comm}\n")
      strass_menu
    when /^comma2mycomm (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.comma2mycomm}\n")
      strass_menu
    when /^comma2char (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.comma2char}\n")
      strass_menu
    when /^comma2join (.+)/i
      foo=$1.chomp
      print_good("#{foo.to_s.comma2join}\n")
      strass_menu
    else
      cls
      print_line("")
      print_error("Oops, Didn't quite understand that one")
      print_error("Please Choose a Valid Option From Menu Below Next Time.....")
      print_line("")
      strass_menu_help
      strass_menu
    end
  end
end

# Basic Usage for Main Menu & General Tools
# This is the sub menu options to help save space as its kind of a lot
# keeps menus broken into categories for ease of use by users
# 1=basic, 2=builder, 3=tamper, 4=append, 5=space, 6=floor, 7=commas, 8=all
def strass_real_usage(num)
  if num.to_i == 1 or num.to_i == 8
    puts "Available Encoder & Decoder Options: ".underline.white
    puts "b64 STR".light_yellow + "        => ".white + "Base64 Encode String".light_red
    puts "b64d STR".light_yellow + "       => ".white + "Base64 Decode String".light_red
    puts "up STR".light_yellow + "         => ".white + "UPPERCASE String".light_red
    puts "down STR".light_yellow + "       => ".white + "lowercase String".light_red
    puts "rev STR".light_yellow + "        => ".white + "esreveR|Reverse String".light_red
    puts "rot13 STR".light_yellow + "      => ".white + "ROT13 Encode/Decode String".light_red
    puts "hex STR".light_yellow + "        => ".white + "HEX Encode String".light_red
    puts "unhex STR".light_yellow + "      => ".white + "HEX to ASCII".light_red
    puts "mysqlhex STR".light_yellow + "   => ".white + "0xMySQL HEX Encode String".light_red
    puts "mysqlunhex STR".light_yellow + " => ".white + "0xMySQL HEX to ASCII".light_red
    puts "ascii STR".light_yellow + "      => ".white + "Returns ASCII Value of String".light_red
    puts "mysqlchar STR".light_yellow + "  => ".white + "Returns MySQL CHAR() Value of String".light_red
    puts "mssqlchar STR".light_yellow + "  => ".white + "Returns MSSQL CHAR() Value of String".light_red
    puts "oraclechar STR".light_yellow + " => ".white + "Returns Oracle CHR() Value of String".light_red
    puts "unicode STR".light_yellow + "    => ".white + "Unicode Encode String".light_red
    puts "urienc STR".light_yellow + "     => ".white + "URI Encode String".light_red
    puts "uridec STR".light_yellow + "     => ".white + "URI Decode String".light_red
    puts "doubleurl STR".light_yellow + "  => ".white + "URI Double Encode String".light_red
    puts "ent_dec STR".light_yellow + "    => ".white + "HTML Entity Decimal Encode String (&#DD)".light_red
    puts "ent_ddec STR".light_yellow + "   => ".white + "HTML Entity Decimal Decode String (&#DD)".light_red
    puts "ent_hex STR".light_yellow + "    => ".white + "HTML Entity HEX Encode String (&#xXX)".light_red
    puts "ent_dhex STR".light_yellow + "   => ".white + "HTML Entity HEX Decode String (&#xXX)".light_red
    puts "ent_name STR".light_yellow + "   => ".white + "HTML Entity Named Encoding of String".light_red
    puts "ent_dname STR".light_yellow + "  => ".white + "HTML Entity Named Decoding of String".light_red
    print_line("")
  end

  # Now print the QUERY BUILDER Functions if requested
  if num.to_i == 2 or num.to_i == 8
    puts "Available SQLi Query Builder Options: ".underline.white
    puts "union NUMBER".light_yellow + "             => ".white + "Union Select Query using provided NUMBER of columns".light_red
    puts "union_null NUMBER".light_yellow + "        => ".white + "Union Select Query with NULL value for provided NUMBER of columns".light_red
    puts "union_cust CUSTOM NUMBER".light_yellow + " => ".white + "Union Select Query with CUSTOM value for provided NUMBER of columns".light_red
    puts "union_bof BUFFER NUMBER".light_yellow + "  => ".white + "BoF Union Select Query using provided BUFFER & NUMBER of Columns".light_red
    print_line("")
  end

  # Now print the SQLi & Tamper Functions if requested
  if num.to_i == 3 or num.to_i == 8
    puts "Available SQLi Tamper Options: ".underline.white
    puts "wafcap STR".light_yellow + "          => ".white + "Randomly Capitalize ALL Words Throughout String".light_red
    puts "wafcap_common STR".light_yellow + "   => ".white + "Randomly Capitalize SQLi Key Words in String".light_red
    puts "doubleup STR".light_yellow + "        => ".white + "Double Up SQLi Key Words (UNunionION)".light_red
    puts "comment STR".light_yellow + "         => ".white + "C Comment SQLi Key Words (/*UNION*/)".light_red
    puts "mycomment STR".light_yellow + "       => ".white + "MySQL Friendly C Style Comment of SQLi Key Words (/*!UNION*/)".light_red
    puts "mykeyhex STR".light_yellow + "        => ".white + "URL Hex Encode SQLi Key Words (U%6eIO%6e S%65L%65CT 1,2,3)".light_red
    puts "zerocomment STR".light_yellow + "     => ".white + "Zero Versioned MySQL Friendly C Style Comment on SQLi Key Words (/*!0UNION*/)".light_red
    puts "randcomment STR".light_yellow + "     => ".white + "C Style Comments Randomly Inserted into SQLi Key Words (U/*N*/IO/*N*/)".light_red
    puts "modsec_vers STR".light_yellow + "     => ".white + "Versioned MySQL C Comments Encapsulating Query String (/*!30187UNION SELECT 1,2,3,4*/)".light_red
    puts "modsec_zerovers STR".light_yellow + " => ".white + "Zero Versioned MySQL C Comments Encapsulating Query String (/*!00000UNION SELECT 1,2,3,4*/)".light_red
    puts "bluecoat STR".light_yellow + "        => ".white + "Bluecoat WAF: Adds Legal ASCII Blank Char following SQLi Key Words (UNION%09 SELECT%09 1,2,3 FROM foo#)".light_red
    puts "securesphere STR".light_yellow + "    => ".white + "Imperva SecureSphere WAF: Appends \"magic\" string to each request (and '0having'='0having')".light_red
    puts "equal2like STR".light_yellow + "      => ".white + "Convert '=' comparison to 'LIKE' comparison".light_red
    puts "gt2between STR".light_yellow + "      => ".white + "Convert '>' comparison to 'NOT BETWEEN' comparison".light_red
    puts "percent STR".light_yellow + "         => ".white + "Places '%' after each char in string (Common ASP Bypass)".light_red
    puts "singleq2utf STR".light_yellow + "     => ".white + "Convert Single Quotes (') to UTF version (%EF%BC%87)".light_red
    puts "singleq2null STR".light_yellow + "    => ".white + "Convert Single Quotes (') to NULL URI Encoded version (%00%27)".light_red
    puts "unmagicquotes STR".light_yellow + "   => ".white + "Convert Single Quotes (') to multi-byte combo (%bf%27)and add dash (--) comment to end to balance".light_red
    print_line("")
  end

  # Now print the Append Functions if requested
  if num.to_i == 4 or num.to_i == 8
    puts "Available Append Options: ".underline.white
    puts "addnull STR".light_yellow + "  => ".white + "Append NULL Byte (%00)".light_red
    puts "adddash STR".light_yellow + "  => ".white + "Append Dash Delimieter (--)".light_red
    puts "addsdash STR".light_yellow + " => ".white + "Append String Based Dash Delimieter (-- -)".light_red
    puts "addhash STR".light_yellow + "  => ".white + "Append Hash/Pound Delimieter (\#)".light_red
    puts "addcomm STR".light_yellow + "  => ".white + "Append MS-SQL Comment Style Delimieter (/*)".light_red
    puts "addsp STR".light_yellow + "    => ".white + "Append sp_password for MS-SQL Log Evasion".light_red
    print_line("")
  end

  # Now print the Space Functions if requested
  if num.to_i == 5 or num.to_i == 8
    puts "Available White Space Manipulation Options: ".underline.white
    puts "space2comment STR".light_yellow + "   => ".white + "Convert Spaces to C Style Comment (' ' => /**/)".light_red
    puts "space2mycomment STR".light_yellow + " => ".white + "Convert Spaces to MySQL Friendly C Style Comment (' ' => /*!*/)".light_red
    puts "space2dash STR".light_yellow + "      => ".white + "Convert Spaces to Dash (--) followed by random string and a new line (ZeroNights: ' ' => --aXyNOfLq%0A)".light_red
    puts "space2dashline STR".light_yellow + "  => ".white + "Convert Spaces to Dash (--) followed by a new line (' ' => --%0A)".light_red
    puts "space2hash STR".light_yellow + "      => ".white + "Convert Spaces to Hash/Pound (\#) followed by random string and a new line (ModSec-Challenge: ' ' => \#aXyNOfLq%0A)".light_red
    puts "space2hashline STR".light_yellow + "  => ".white + "Convert Spaces to Hash/Pound (\#) followed by a new line (' ' => \#%0A)".light_red
    puts "space2mssql STR".light_yellow + "     => ".white + "Convert Spaces to any 1 of 15 possible chars considered legal by MS-SQL".light_red
    puts "space2mysql STR".light_yellow + "     => ".white + "Convert Spaces to any 1 of 6 possible chars considered legal in MySQL".light_red
    puts "space2rand STR".light_yellow + "      => ".white + "Convert Spaces to any 1 of 4 possible chars considered universally legal".light_red
    puts "space2oa STR".light_yellow + "        => ".white + "Convert Spaces to New Line (%0A)".light_red
    puts "space2o9 STR".light_yellow + "        => ".white + "Convert Spaces to Horizontal Tab (%09)".light_red
    puts "space2ob STR".light_yellow + "        => ".white + "Convert Spaces to Vertical Tab (%0B)".light_red
    puts "space2oc STR".light_yellow + "        => ".white + "Convert Spaces to New Page (%0C)".light_red
    puts "space2od STR".light_yellow + "        => ".white + "Convert Spaces to Carriage Return (%0D)".light_red
    puts "space2plus STR".light_yellow + "      => ".white + "Convert Spaces to Plus (+)".light_red
    print_line("")
  end

  # Now print the FLOOR(RAND(0)*2) Functions if requested
  if num.to_i == 6 or num.to_i == 8
    puts "Available FLOOR(RAND(0)*2) Manipulation Options: ".underline.white
    puts "floor2xor STR".light_yellow + "      => ".white + "Convert FLOOR(RAND(0)*2) to RAND(0) XOR 1".light_red
    puts "floor2greatest STR".light_yellow + " => ".white + "Convert FLOOR(RAND(0)*2) to GREATEST(rand(0),2)".light_red
    puts "floor2div STR".light_yellow + "      => ".white + "Convert FLOOR(RAND(0)*2) to RAND(0) div 1".light_red
    puts "floor2round STR".light_yellow + "    => ".white + "Convert FLOOR(RAND(0)*2) to ROUND(RAND(0),2)".light_red
    puts "floor2rand STR".light_yellow + "     => ".white + "Convert FLOOR(RAND(0)*2) to RAND(0) | RAND(0)".light_red
    print_line("")
  end

  # Now print the FLOOR(RAND(0)*2) Functions if requested
  if num.to_i == 7 or num.to_i == 8
    puts "Available Comma Manipulation Options: ".underline.white
    puts "comma2comm STR".light_yellow + "   => ".white + "C Style Comment out commas (,) to (/*,*/)".light_red
    puts "comma2mycomm STR".light_yellow + " => ".white + "MySQL Friendly C Style Comment out commas (,) to (/*!,*/)".light_red
    puts "comma2char STR".light_yellow + "   => ".white + "Add mysql char(44) after each comma (',') in hopes it remains after normal comma stripped by WAF".light_red
    puts "comma2join STR".light_yellow + "   => ".white + "Convert basic Union Select 1,2,3 Query to join statements (union (select 1)a join (select 2)b join (select 3)c)".light_red
    print_line("")
  end
end
