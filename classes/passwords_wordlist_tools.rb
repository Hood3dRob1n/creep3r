# Password and Wordlist Tools
# Functions and Classes should be made available to tool
# Primarlily access from passwords_ui


# This is our hasher function
# It takes a string and displays it along with multiple hash formats
# Usefull for all kinds of reasons...
def hasher(string)
  puts
  puts "[".light_blue + "*".white + "]".light_blue + " Hash Generator Results for: #{string}".white
  puts "############################################################".light_blue
  puts "Rot13".light_blue + ":   #{string.rot13}".white
  puts "Base64".light_blue + ":  #{string.b64e.chomp}".white
  puts "Hex".light_blue + ":     #{string.hexme}".white
  puts "0xHex".light_blue + ":   #{string.mysqlhex}".white
  puts "DES".light_blue + ":     #{des_crypt(string)}".white
  puts "ASCII".light_blue + ":   #{string.asciime}".white
  puts "MD4".light_blue + ":     #{md4(string)}".white
  puts "MD5".light_blue + ":     #{md5(string)}".white
  begin
    puts "LM".light_blue + ":      #{lm(string)}".white
    puts "NTLM".light_blue + ":    #{ntlm(string)}".white
  rescue Iconv::IllegalSequence
    puts "Skipping LM|NTLM Hashing of #{entry} due to issues with encoding, sorry....."
  end
  puts "SHA1".light_blue + ":    #{sha1(string)}".white
  puts "MySQL5".light_blue + ":  #{mysql5_hash(string)}".white
  puts "Unicode".light_blue + ": #{string.unicode}".white
  puts "Bcrypt".light_blue + ":  #{bcrypt(string)}".white
  puts "Joomla!".light_blue + ": #{joomla_hash(string)}".white
  begin
    puts "LM:NTLM".light_blue + ": #{ntlm_gen(string)}".white
  rescue Iconv::IllegalSequence
    puts "Skipping LM:NTLM Hashing of #{entry} due to issues with encoding, sorry....."
  end
  puts "SHA256".light_blue + ":  #{sha256(string)}".white
  puts "SHA512".light_blue + ":  #{sha512(string)}".white
  puts "############################################################\n".light_blue
end

# Try to identify hash string provided...
# Not perfect but tries to help...
# Provide hash string, filter if applicable
# Can disable verbose if needed for inclusion in plugin
# Returns array with match results [ strong, medium, weak ]
def identifyme(hash, filter=nil, verbose=true)
  strong=[] # 90%+ matches based on filter and real world usage likeliness
  medium=[] # 90% match but matches more than one type
  weak=[]   # Possible Match, long shot kind of

  # MD5/MD4
  if hash =~ /[a-fA-F\d]{32}/ and hash.size == 32
    case filter
    when 'OTHER', 'WEB'
      strong << 'MD5'
      medium << 'MD4'
    else
      medium << 'MD5'
      weak << 'MD4'
    end
  end

  # LM/NTLM
  if hash =~ /[a-fA-F\d]{32}(?![a-fA-F0-9])/ and hash.size == 32
    case filter
    when 'WIN'
      if hash =~ /[A-F0-9]{32}/
        strong << 'LM'
        strong << 'NTLM'
      else
        medium << 'LM'
        medium << 'NTLM'
      end
    else
      if hash =~ /[A-F0-9]{32}/
        medium << 'LM'
        medium << 'NTLM'
      else
        weak << 'LM'
        weak << 'NTLM'
      end
    end
  end

  # Alternative NTLM Hash format with $NT prefix
  if hash =~ /^\$NT\$[a-fA-F\d]{32}(?![a-fA-F0-9])/ and hash.size == 36
    case filter
    when 'WIN'
      strong << 'NTLM'
    else
      if hash =~ /^\$NT\$[A-F0-9]{32}/
        medium << 'NTLM'
      else
        weak << 'NTLM'
      end
    end
  end

  # MySQL 5+
  if hash =~ /\*[a-fA-F\d]{40}/ and hash.size == 41
    if hash =~ /\*[A-F0-9]{40}/
      strong << 'MySQL 4+'
      medium << 'SHA1'
    else
      medium << 'MySQL 4+'
      weak << 'SHA1'
    end
  end

  # MySQL 323
  if hash =~ /[a-fA-F\d]{16}/ and hash.size == 16
    case filter
    when 'OTHER', 'WEB'
      strong << 'MySQL 323'
    else
      medium << 'MySQL 323'
    end
  end

  # Cisco-PIX MD5 
  if hash =~ /[a-zA-Z\d]{16}/ and hash.size == 16
    case filter
    when 'UNIX'
      strong << 'Cisco-PIX MD5'
    when 'WIN'
      weak << 'Cisco-PIX MD5'
    else
      medium << 'Cisco-PIX MD5'
    end
  end

  # BSDI crypt()
  if hash.size == 20 and hash =~ /[a-zA-Z0-9_\.\/]{20}/
    case filter
    when 'UNIX'
      strong << 'BSDI crypt'
    when 'WIN'
      weak << 'BSDI crypt'
    else
      medium << 'BSDI crypt'
    end
  end

  # Juniper NetscreenOS MD5 hash
  if hash =~ /n[a-zA-Z0-9\.\+\/]{28}n/
    if (hash =~ /\w+\$n[a-zA-Z0-9\.\+\/]{28}n/) or (hash =~ /\w+:\w+\$n[a-zA-Z0-9\.\+\/]{28}n/) or (hash =~ /n[a-zA-Z0-9\.\+\/]{28}n/ and hash.size == 30)
      strong << 'Juniper Netscreen MD5'
    else
      case filter
      when 'WIN', 'WEB', 'OTHER'
        weak << 'Juniper Netscreen MD5'
      else
        medium << 'Juniper Netscreen MD5'
      end
    end
  end

  # Unix DES, crypt()
  if hash =~ /(?<![a-zA-Z0-9.\/$])[a-zA-Z0-9.\/]{13}(?![a-zA-Z0-9.\/])/ and hash.size == 13
    case filter
    when 'OTHER', 'UNIX', 'WEB'
      strong << 'Unix DES'
    else
      medium << 'Unix DES'
    end
  end

  # Mac OS-X Salted SHA1 ( OS X v10.4, v10.5, v10.6 )
  if hash =~ /[0-9A-Fa-f]{48}/ and hash.size == 48
    case filter
    when 'OTHER', 'UNIX'
      if hash =~ /[0-9A-F]{48}/
        strong << 'Mac OS X v10.4, v10.5, v10.6 Salted SHA1'
      else
        medium << 'Mac OS X v10.4, v10.5, v10.6 Salted SHA1'
      end
    else
      weak << 'Mac OS X v10.4, v10.5, v10.6 Salted SHA1'
    end
  end

  # Mac OS X v10.7
  if hash =~ /[0-9A-Fa-f]{136}/ and hash.size == 136
    case filter
    when 'OTHER', 'UNIX'
      strong << 'Mac OS X v10.7'
    else
      weak << 'Mac OS X v10.7'
    end
  end

  # Base64
  if hash =~ /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})$/
    if hash =~ /==$/
      if hash.size == /32|40|41|48|49|56|61|64|65|96|128/
        weak << 'Base64'
      else
        strong << 'Base64'
      end
    else
      if hash.size == 24 or hash.size == 32 or hash.size == 40 or hash.size == 41 or hash.size == 46 or hash.size == 48 or hash.size == 49 or hash.size == 56 or hash.size == 61 or hash.size == 64 or hash.size == 65 or hash.size == 96 or hash.size == 128
        weak << 'Base64'
      else
        medium << 'Base64'
      end
    end
  end

  # bigcrypt (DES) & crypt16
  # Some random possibilities, unlikely but possibly (HP-UX/Tru64)
  if hash =~ /[a-zA-Z0-9\.\/]{24}/ and hash.size == 24
    case filter
    when 'OTHER', 'UNIX', 'WEB'
      medium << 'bigcrypt DES'
      medium << 'crypt16'
    else
      weak << 'bigcrypt DES'
      weak << 'crypt16'
    end
  end

  # SHA1
  if hash =~ /[a-fA-F\d]{40}/ and hash.size == 40
    strong << 'SHA1'
  end

  # SHA224
  if hash =~ /[a-fA-F\d]{56}/ and hash.size == 56
    strong << 'SHA224'
  end

  # SHA256
  if hash =~ /[a-fA-F\d]{64}/ and hash.size == 64
    strong << 'SHA256'
  end

  # SHA384
  if hash =~ /[a-fA-F\d]{96}/ and hash.size == 96
    strong << 'SHA384'
  end

  # SHA512 or Whirlpool
  if hash =~ /[a-fA-F\d]{128}/ and hash.size == 128
    if hash =~ /[A-F\d]{128}/
      strong << 'SHA512'
      medium << 'Whirlpool'
    else
      strong << 'Whirlpool'
      medium << 'SHA512'
    end
  end

  if hash =~ /sha\d+\$\$[a-zA-Z0-9]{40,96}/
    if hash =~ /sha1\$\$[a-zA-Z0-9]{40}/ and hash.size == 46
      strong << 'Django SHA1'
    elsif hash =~ /sha256\$\$[a-zA-Z0-9]{64}/ and hash.size == 72
      strong << 'Django SHA256'
    elsif hash =~ /sha384\$\$[a-zA-Z0-9]{96}/ and hash.size == 104
      strong << 'Django SHA384'
    elsif hash =~ /sha512\$\$[a-zA-Z0-9]{128}/ and hash.size == 136
      strong << 'Django SHA512'
    else
      if filter == 'WEB'
        medium << 'Django SHA hash of some kind'
      else
        weak << 'Django SHA hash of some kind'
      end
    end
  end

  # Unix Salted SHA256
  if (hash =~ /\$5\$[a-zA-Z0-9.\/]{8,16}\$[a-zA-Z0-9.\/]{43}(?![a-zA-Z0-9.\/])/) or (hash =~ /\$5\$rounds=\d+\$[a-zA-Z0-9\.\/]{8,16}\$[a-zA-Z0-9\.\/]{38,43}/)
    case filter
    when 'OTHER', 'UNIX', 'WEB'
      strong << 'Unix SHA256'
    else
      medium << 'Unix SHA256'
    end
  end

  # Unix Salted SHA512
  if (hash =~ /\$6\$[a-zA-Z0-9.\/]{8,16}\$[a-zA-Z0-9.\/]{86}(?![a-zA-Z0-9.\/])/) or (hash =~ /\$6\$rounds=\d+\$[a-zA-Z0-9\.\/]{8,16}\$[a-zA-Z0-9\.\/]{86}/)
    case filter
    when 'OTHER', 'UNIX', 'WEB'
      strong << 'Unix SHA512'
    else
      medium << 'Unix SHA512'
    end
  end

  # Apache MD5
  if hash =~ /\$apr1\$[a-zA-Z0-9.\/]{8}\$[a-zA-Z0-9.\/]{22}(?![a-zA-Z0-9.\/])/
    case filter
    when 'OTHER', 'UNIX', 'WEB'
      strong << 'Apache MD5'
    else
      medium << 'Apache MD5'
    end
  end

  # Unix MD5
  if hash =~ /\$1\$[a-zA-Z0-9.\/]{8}\$[a-zA-Z0-9.\/]{22}(?![a-zA-Z0-9.\/])/
    case filter
    when 'OTHER', 'UNIX', 'WEB'
      strong << 'Unix MD5'
    else
      medium << 'Unix MD5'
    end
  end

  # Wordpress or phpBB3 MD5
  if hash =~ /\$[a-zA-Z0-9.\/]{31}(?![a-zA-Z0-9.\/])/
    match=false
    # Wordpress MD5
    if hash =~ /\$P\$[a-zA-Z0-9.\/]{31}(?![a-zA-Z0-9.\/])/
      match=true
      case filter
      when 'OTHER', 'WEB'
        strong << 'Wordpress MD5'
      else
        medium << 'Wordpress MD5'
      end
    end
    # phpBB3 MD5
    if hash =~ /\$H\$[a-zA-Z0-9.\/]{31}(?![a-zA-Z0-9.\/])/
      match=true
      case filter
      when 'OTHER', 'WEB'
        strong << 'phpBB3 MD5'
      else
        medium << 'phpBB3 MD5'
      end
    end
    if not match
      weak << 'phpBB3 MD5'
      weak << 'Wordpress MD5'
    end
  end

  # Joomla Salted MD5 (md5:md5) or Windows LM:NTLM
  if hash =~ /[a-zA-Z0-9.\/]{32}:[a-zA-Z0-9.\/]{32}/ and hash.size == 65
    case filter
    when 'WIN'
      if hash =~ /[a-fA-F\d]{32}:[a-fA-F\d]{32}/
        strong << 'LM:NTLM'
      end
      medium << 'Joomla v2'
    when 'WEB'
      strong << 'Joomla v2'
      if hash =~ /[a-fA-F\d]{32}:[a-fA-F\d]{32}/
        weak << 'LM:NTLM'
      end
    else
      medium << 'Joomla v2'
      if hash =~ /[a-fA-F\d]{32}:[a-fA-F\d]{32}/
        medium << 'LM:NTLM'
      end
    end
  end

  # Joomla v1
  if hash =~ /[a-zA-Z0-9.\/]{32}:[a-zA-Z0-9.\/]{16}/ and hash.size == 49
    case filter
    when 'WEB'
      strong << 'Joomla v1'
    else
      medium << 'Salted MD5'
      weak << 'Joomla v1'
    end
  end

  # Bcypt or Unix Blowfish
  if hash =~ /\$2[ay]\$\d\d\$[a-zA-Z0-9.\/]{53}(?![a-zA-Z0-9.\/])/ and hash.size == 60
    case filter
    when 'Unix'
      strong << 'Unix Blowfish or Bcypt'
    when 'Win'
      weak << 'Bcypt or Unix Blowfish'
    else
      medium << 'Bcypt or Unix Blowfish'
    end
  end

  # Various Salted MD5 Formats
  # Try to identify the better known ones where possible...
  if hash =~ /^[a-zA-Z0-9]{32}:.+/
    strong << 'Salted MD5'
    if hash =~ /[a-zA-Z0-9]{32}:[a-zA-Z0-9]{2}/
      if filter == 'WEB' or filter == 'OTHER'
        medium << 'osCommerce'
      else
        weak << 'osCommerce'
      end
    end
    if hash =~ /[a-zA-Z0-9]{32}:[a-zA-Z0-9]{5}/
      if filter == 'WEB' or filter == 'OTHER'
        medium << 'IPB2+, MyBB1.2+'
      else
        weak << 'IPB2+, MyBB1.2+'
      end
    end
    if hash =~ /[a-zA-Z0-9]{32}:[a-zA-Z0-9]{3}/
      if filter == 'WEB' or filter == 'OTHER'
        medium << 'vBulletin < v3.8.5'
      else
        weak << 'vBulletin < v3.8.5'
      end
    end
    if hash =~ /[a-zA-Z0-9]{32}:[a-zA-Z0-9]{30}/
      if filter == 'WEB' or filter == 'OTHER'
        medium << 'vBulletin >= v3.8.5'
      else
        weak << 'vBulletin >= v3.8.5'
      end
    end
  end

  # Various Salted SHA1 Formats
  # Try to identify the better known ones where possible...
  if hash =~ /^[a-zA-Z0-9]{40}:.+/
    strong << 'Salted SHA1'
    if hash =~ /[a-zA-Z0-9]{40}:[a-zA-Z0-9]{8}/
      if filter == 'WEB' or filter == 'OTHER'
        medium << 'SMF >= v1.1'
      else
        weak << 'SMF >= v1.1'
      end
    end
    if hash =~ /[a-zA-Z0-9]{40}:[a-zA-Z0-9]{20}/
      if filter == 'WEB' or filter == 'OTHER'
        medium << 'Oracle 11G'
      else
        weak << 'Oracle 11G'
      end
    end
  end

  # Oracle 7-10G
  if hash =~ /[a-zA-Z0-9]{16}:[a-zA-Z0-9]{10}/ and hash.size == 27
    strong << 'Oracle 7-10G'
  end

  # MS-SQL 2000, 2005 & 2012 Hashes
  if hash =~ /0x0[12]00[a-zA-Z0-9]{8}[a-zA-Z0-9]{40,128}/
    if hash =~ /0x0100[a-zA-Z0-9]{8}[a-zA-Z0-9]{40}[a-zA-Z0-9]{40}/ and hash.size == 94
      if filter == 'UNIX'
        weak << 'MS-SQL 2000'
      elsif filter == 'WIN'
        strong << 'MS-SQL 2000'
      else
        medium << 'MS-SQL 2000'
      end
    elsif hash =~ /0x0100[a-zA-Z0-9]{8}[a-zA-Z0-9]{40}/ and hash.size == 54
      if filter == 'UNIX'
        weak << 'MS-SQL 2005'
      elsif filter == 'WIN'
        strong << 'MS-SQL 2005'
      else
        medium << 'MS-SQL 2005'
      end
    elsif hash =~ /0x0200[a-zA-Z0-9]{8}[a-zA-Z0-9]{128}/ and hash.size == 142
      if filter == 'UNIX'
        weak << 'MS-SQL 2012'
      elsif filter == 'WIN'
        strong << 'MS-SQL 2012'
      else
        medium << 'MS-SQL 2012'
      end
    end
  end

  # Possible Sybase DB Hash
  if hash =~ /0x[a-zA-Z0-9]{84}/ and hash.size == 86
    if not hash =~ /^0x0[12]00/
      case filter
      when 'UNIX'
        strong << 'Sybase'
      else
        medium << 'Sybase'
      end
    else
      case filter
      when 'WIN', 'WEB'
        medium << 'Sybase'
      else
        weak << 'Sybase'
      end
    end
  end

  # Check if match(es) found, if so present them
  print_status("Provided Hash: #{hash}") if verbose
  if weak.empty? and medium.empty? and strong.empty?
    print_error("Sorry - Unable to Identify Provided Hash String!") if verbose
  else
    if strong.size > 0
      print_good("Likey Hash Type: #{strong.uniq.join(', ')}") if verbose
    end
    if medium.size > 0
      print_caution("Possible Hash Type: #{medium.uniq.join(', ')}") if verbose
    end
    if weak.size > 0
      print_error("Other Matches: #{weak.uniq.join(', ')}") if verbose
    end
  end
  return strong, medium, weak
end

# Simple Password Hash Cracker
# MD5, SHA1, SHA512, LM, NTLM Hash formats Supported...
# I'm sure there are many faster options, but it's here if you need it ;)
# Add more if you like....
def simple_crack(hash_type, hashes=[], wordlists=[])
  cracked=[]
  outdir = RESULTS + 'cracked/'
  supported = [ 'MD5', 'SHA1', 'SHA512', 'LM', 'NTLM' ]
  if supported.include?(hash_type)
    while(true)
      print_status("Hash Format: #{hash_type}")
      print_status("#{hashes.size} hash loaded...") if hashes.size == 1
      print_status("#{hashes.size} hashes loaded...") unless hashes.size == 1
      print_status("#{wordlists.size} Wordlists loaded...") unless wordlists.size == 1
      print_status("Running Cracker, hang tight for a bit....")
      wordlists.each do |pass_list|
        print_status("Loaded #{pass_list}...")
        break if hashes.nil? or hashes.empty?
        f = File.open(pass_list)
        f.each do |pass|
          case hash_type
          when 'NTLM'
            amicracked = pass.strip.chomp.ntlm
          when 'LM'
            amicracked = pass.strip.chomp.lm
          when 'SHA512'
            amicracked = pass.strip.chomp.sha512
          when 'SHA1'
            amicracked = pass.strip.chomp.sha1
          when 'MD5'
            amicracked = pass.strip.chomp.md5
          end
          if hashes.include?(amicracked)
            print "\r   [".light_green + "+".white + "] ".light_green + "#{amicracked}".light_red + ":".white + "#{hash_type}".light_yellow + ":".white + "#{pass.strip.chomp}\n".light_green
            cracked << "#{amicracked}:#{hash_type}:#{pass.strip.chomp}"
            hashes.delete(amicracked)
          else
            stuff=['/','|','-','\\']
            print "\r   [".light_blue + "#{stuff[rand(stuff.size)]}".white + "]".light_blue
          end
          break if hashes.nil? or hashes.empty?
        end
        f.close
      end
      break
    end
    # Log the cracked hashes to file, if any...
    if cracked.size > 0
      Dir.mkdir(outdir) unless File.exists?(outdir) and File.directory?(outdir)
      out = outdir + "#{hash_type.downcase}.cracked"
      f = File.open(out, 'a+')
      cracked.uniq.each {|x| f.puts x }
      f.close
      puts "\n\n"
      print_status("Cracked #{cracked.uniq.size} unique hash(es)....")
      print_status("Results saved to: #{out}")
    else
      puts
      print_error("Sorry, no luck today....\n")
    end
  else
    print_error("WTF is #{hash_type}?")
    print_error("Unsupported Hash Format Requested!\n")
  end
end

# Simple Cracker for Password Protected Zip Archives
# Only Traditional (weak) encryption is supported
def zip_crack(zip_file, wordlists=[])
  cracked = false
  outdir = RESULTS + 'cracked/'
  Dir.mkdir(outdir) unless File.exists?(outdir) and File.directory?(outdir)
  print_status("Zip Archive: #{zip_file}")
  while(true)
    print_status("#{wordlists.size} Wordlists loaded...") unless wordlists.size == 1
    print_status("Launching Zip Archive Cracker, hang tight for a bit....")
    wordlists.each do |pass_list|
      puts "\r   [".light_blue + "+".white + "]".light_blue + " Loaded #{pass_list}...".white
      f = File.open(pass_list)
      f.each do |pass|
        begin
          Archive::Zip.extract(zip_file, outdir + zip_file.strip.chomp.split('/')[-1].split('.')[0], :password => pass.strip.chomp)
          puts "\r   [".light_green + "+".white + "]".light_green + " Zip Cracked w/Password: #{pass.strip.chomp}".white
          puts "   [".light_green + "+".white + "]".light_green + " Content Extracted to: #{outdir + zip_file.strip.chomp.split('/')[-1].split('.')[0]}\n".white
          cracked = true
          break
        rescue => e
          stuff=['/','|','-','\\']
          print "\r   [".light_blue + "#{stuff[rand(stuff.size)]}".white + "]".light_blue
        end
      end
      f.close
      break if cracked
    end
    break
  end
  if cracked
    return true
  else
    puts "\r   [".light_red + "x".white + "]".light_red + " Did NOT find password in wordlist(s)!\n".white
    if File.exists?(outdir + zip_file.strip.chomp.split('/')[-1].split('.')[0]) and File.directory?(outdir + zip_file.strip.chomp.split('/')[-1].split('.')[0])
      FileUtils.rm_rf(outdir + zip_file.strip.chomp.split('/')[-1].split('.')[0]) # Cleanup partial extractions of junk data
    end
    return false
  end
end
